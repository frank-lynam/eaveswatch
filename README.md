# hobkin-eaveswatch

Logs, deploys and connections from every host, joined to the code that made
them, for a [hobkin](https://github.com/frank-lynam/hobkin) to review.

Scanners look at one thing at a time: a diff, a dependency, a log line. The
interesting problems are joins: *this commit changed the retry, and since
Tuesday's deploy that error is 40× an hour from that code path*; *flow data
shows web-3 talking to the admin DB, and nothing in the code says it should*.
eaveswatch gathers what's needed to see those, and hands it to a reviewer
agent with a bar for what counts as a finding and a ledger that traces every
conclusion back to its evidence.

- **Eaves** run on every host. No model, no key. They read log files and
  journald, redact secrets **on the host**, and turn lines into templates with
  counts (flagging new and spiking ones against the host's own baseline). They
  note what's deployed (the git SHA of each service, units, containers) and
  who the host talks to (`ss`). Everything goes to the store as gzipped JSON lines.
- **The ridge** is the hub: a plain loop pulls new files from the store into a
  data folder. Then a hobkin with the `eaveswatch` chore wakes on a digest of
  what's new, keeps the system map, connects log lines to the code at the
  version that wrote them, and records findings.
- **Same module everywhere.** One stdlib-only Python file (3.9+), three roles:
  `eave`, `ridge`, `local` (both on one box, with a folder for a store). A
  ridge can be an eave of a bigger roof.

## The store

A folder, or `s3://bucket/prefix`. Hive-style prefixes, so Athena and Glue can
query the archive as it is:

```
PREFIX/env=prod/kind=packets/dt=2026-11-14/hour=09/host=web-3/web-3_20261114T091502Z_7f3a.jsonl.gz
```

- **Time before host:** the ridge lists one hour across every host. IAM can
  still hold each eave to its own host (`*/host=web-3/*`).
- **The name stands alone:** host, UTC stamp (sorts as text, no colons), a
  random suffix so two writes in one second never collide.
- **Kinds:** `packets` (templates, counts, new and spiking), `inventory`,
  `flows`, `raw` (opt-in per source: redacted lines, the archive), `requests`
  (ridge → eave) and `answers` (eave → ridge).
- **Retention** is S3 lifecycle rules (say, `kind=raw` to Glacier after 30
  days), not code.

No boto3: requests are signed with SigV4 in the standard library. Credentials
come from the environment, `~/.aws/credentials` (`AWS_PROFILE`), the ECS task
role, or the instance role (IMDSv2). `"endpoint"` points it at MinIO or
another S3-compatible store.

## Try it on one box

```sh
cat > eaveswatch.json <<'EOF'
{"role": "local", "env": "dev", "store": "~/eaveswatch/store", "state_dir": "~/eaveswatch/state",
 "sources": [{"name": "journal", "journald": true}],
 "services": {"myapp": {"dir": "~/src/myapp"}}}
EOF
python3 eaveswatch.py local --once        # an eave tick and a ridge sync
python3 eaveswatch.py ridge watch         # the digest: what's new (nothing new: prints nothing)
```

An eave spends its first hour (`warmup_minutes`) learning what's usual, so
nothing is flagged "new" until then.

## A fleet

On every host: copy `eaveswatch.py` to `/usr/local/bin/eaveswatch` (or `pipx
install hobkin-eaveswatch`), write `/etc/eaveswatch.json` (see
[examples/eave.json](examples/eave.json)), and run
[examples/eaveswatch-eave.service](examples/eaveswatch-eave.service), as a user
that can read the logs and nothing else.

On the ridge, two pieces, deliberately apart:

1. **The sync loop**, with the store's credentials and no model:
   `eaveswatch --config /etc/eaveswatch.json ridge` (the same unit, `ridge`
   for `eave`; see [examples/ridge.json](examples/ridge.json)).
2. **The reviewer**, a hobkin with no store credentials and no network for its
   commands (safe mode). It only reads the data folder:

   ```sh
   hobkin --chore /path/to/hobkin-eaveswatch/chore/eaveswatch \
     --set config=/etc/eaveswatch.json --set data=/srv/eaveswatch-ridge \
     --set repos="/srv/code" --id eaveswatch --safe
   ```

   Start the sync loop first: it creates the data folder, and safe mode
   won't start an agent whose write folder doesn't exist yet.
   Its watch runs `eaveswatch ridge watch` every 5 minutes and wakes it only
   when there's a digest. Quiet periods cost no model calls.

### IAM, least privilege

| Who | Allow |
|---|---|
| eave `web-3` | `s3:PutObject` on `PREFIX/*/host=web-3/*`; `s3:ListBucket` with `s3:prefix` `PREFIX/env=prod/kind=requests/*`; `s3:GetObject` on `PREFIX/env=*/kind=requests/*/host=web-3/*` |
| ridge sync | `s3:ListBucket` and `s3:GetObject` on `kind=packets`, `inventory`, `flows`, `answers`; `s3:PutObject` on `kind=requests` |
| ridge, never | `kind=raw` (the archive is for people; the reviewer asks an eave for lines instead) |

## What the reviewer does

The chore ([chore/eaveswatch/CHORE.md](chore/eaveswatch/CHORE.md)) has the full instructions. In short:

- **The map** (`DATA/map/`) builds itself from eave reports: `hosts.json`
  (what runs where, at which version, last seen), `edges.json` (listeners,
  and who talks to whom), `templates.json` (every log template, its hosts and
  versions). Packets carry the `service` and `version` that wrote each line,
  so a log line points straight at the code.
- **The digest** says what changed: new hosts, hosts gone quiet, deploys,
  new connections and listeners, spiking and new log templates, answers to asks.
- **Asks** go to an eave from a fixed menu, never a shell: `eaveswatch ask
  HOST lines FP` (matching lines from its logs, redacted), `ask HOST
  inventory`, `ask HOST flows`. The answer comes back in a later digest.
- **A finding** needs evidence, a failure scenario, an action and a
  confidence. Without all four it's an observation in the agent's notes.
  Before recording, it gets a brownie to try to knock the finding down, and
  it records at most three per digest.
- **The ledger** (`DATA/findings.jsonl`) is append-only events. The same
  category and location is the same finding (counted again, not duplicated).
  A dismissal needs a reason, and isn't recorded again. Each finding carries
  its inputs (store files) and the charter version (`DATA/REVIEW.md`).

```sh
eaveswatch finding add < finding.json
eaveswatch finding list [--all]
eaveswatch finding status F-1a2b3c4d dismissed --why "behind the VPN only"
```

- **Visibility gaps are findings too** (category `visibility`): a host with no
  eave, logs without a version, an auth path that logs nothing. Each comes
  with the exact change as a reviewable diff. The reviewer never applies those
  changes itself.

## Security model

- Secrets are redacted on the host before anything is written: private keys,
  AWS key ids, JWTs, bearer tokens, `password=`/`token=`/`api_key=` values,
  `user:pass@` in URLs, plus your own patterns (`"redact"`). Raw lines stay on
  the host unless a source is listed in `"raw"`.
- Logs, commit messages and requests are written by others, attackers
  included. The reviewer treats them as data: no store credentials, no
  network for its commands, writes only in its data folder, and asks eaves
  only from a fixed menu.
- Logs leave the host only as far as your bucket. Where the model runs is
  your choice in hobkin's config (Bedrock in-region, for one).

## Config

| Setting | Default | |
|---|---|---|
| `role` | `eave` | `eave`, `ridge` or `local` |
| `env` | `prod` | the `env=` prefix: one store, several environments |
| `host` | hostname | the `host=` prefix |
| `store` | | a folder, or `s3://bucket/prefix` |
| `region`, `endpoint` | `$AWS_REGION` | S3 region; an S3-compatible endpoint (path-style) |
| `state_dir` | `/var/lib/eaveswatch` | offsets, cursors, baselines; the ridge's data default |
| `every` | `60` | seconds between ticks |
| `sources` | `[]` | `{"name", "path": glob}` or `{"name", "journald": true, "units": [...]}`; `"service"` ties a source to one in `services`; `"from_start"` reads a new file from its start |
| `services` | `{}` | `{"api": {"dir": "/srv/api"}}` (git SHA) or `{"version_file": ...}` |
| `raw` | `[]` | source names archived as redacted lines |
| `redact` | `[]` | extra regexes |
| `spike` | `4.0` | × the usual count (and at least 10) |
| `warmup_minutes` | `60` | learning time before "new" means anything |
| `inventory_every` | `3600` | inventory and flows: on change, and at least this often |
| `ridge` | | `data` (folder), `envs` (which to read), `silent_after` (seconds) |

## Tests

`python3 tests/test_eaveswatch.py`: the text helpers, the layout, AWS's own
SigV4 test vector, and a full eave → store → ridge round trip (asks, deploys
and findings included) on a folder and on a fake S3 that checks every
signature. No AWS, no cost.
