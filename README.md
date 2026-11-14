# hobkin-eaveswatch

Logs, deploys, config and connections, joined to the code that made them, for a
[hobkin](https://github.com/frank-lynam/hobkin) to set up and review.

Scanners look at one thing at a time: a diff, a dependency, a log line. The
interesting problems are joins: *since Tuesday's config change that error is
40× an hour*; *the box listens on a port nobody mentioned*. eaveswatch gathers
what's needed to see those and hands it to a reviewer agent. The agent works
out what's worth collecting and how to read it. It gets a bar for what counts as
a finding, and a ledger that traces every conclusion back to its evidence.

- **No hand-written log config.** The reviewer hobkin runs `discover`:
  - which services run here, and what they run
  - which files each one has open for writing
  - which ports they listen on and talk to
  - which config files they point at
  - who writes to the journal

  It asks you what you care about, then writes an **interpreter spec**: JSON
  that names the sources and says how to read them. That means multi-line
  entries, timestamps, levels, placeholders for what varies, noise to drop,
  where versions come from, and which config files to watch. `interpret test`
  replays the real recent lines through it; `interpret apply` makes it the
  active, numbered version.
- **No model per line, and no code from the model.** The eave runs the active
  spec's patterns in plain code. Patterns that backtrack forever are caught in
  testing.
- **Secrets never leave**, whatever the spec says. A built-in redaction floor
  always runs first. It catches private keys, AWS key ids, JWTs, bearer
  tokens, `password=`/`token=` values, `PS_TOKEN`/`JSESSIONID`, `user:pass@`
  in URLs and long base64 blobs. A spec can add patterns but never remove
  them. Credential files and folders (`~/.ssh`, `~/.aws`, key files,
  `~/.hobkins`...) are refused as sources.
- **Same module everywhere**, one standard-library Python file (3.9+), three roles:

| Role | Where | What |
|---|---|---|
| `finial` | one box, all of it | eave, ridge and reviewer together; files to S3 (the archive) and straight to the reviewer |
| `eave` | every host of a fleet | its interpreter's sources, inventory, flows → the store; answers asks |
| `ridge` | a fleet's hub | the store → a data folder for the reviewer; asks → the store |

(A finial is the ornament at the very top of a single roof.)

## A finial: one box, watched from the inside

As **the same user the watched services run as** (with those services as user
systemd units), run:

```sh
pipx install hobkin-eaveswatch          # brings hobkin too
eaveswatch https://openrouter.ai/api/v1 anthropic/claude-sonnet-4.5 sk-or-...    # the reviewer's model API
```

Running as that user lets discovery see the services' own open files,
sockets and environment, with no root and no extra capabilities.

The one command asks which S3 bucket to use (showing the ones it can see).
Everything else is decided for you:
- **Region:** the bucket's own.
- **Credentials:** the instance profile.
- **Host:** the hostname.
- **Config:** `~/.config/eaveswatch/finial.json`.
- **State:** `~/eaveswatch`. It isn't under a dot-folder on purpose: hobkin's
  safe mode refuses write folders inside `~/.something`, because those are
  ways out of the sandbox.

It runs `check`, installs and starts the `eaveswatch-finial` user service,
turns on lingering (so the services run with nobody logged in), installs the
reviewer chore, and hands over to hobkin. You end up in a chat with the
reviewer. Run it again later and it reuses the same setup.

Options:
- `--bucket NAME`, so nothing is asked
- `--store s3://bucket/prefix`, or a folder to try it without S3
- `--env`, `--host`
- `--no-service`, `--no-chat`
- `--force` (replace an existing setup)

The reviewer then:
1. runs `discover`
2. tells you in a few lines what it found ("a PeopleSoft app server domain
   HRDEV, a PIA on 8000...")
3. proposes what to collect, watch and archive, with a recommendation for each
4. asks what you care about
5. writes, tests and applies the interpreter, and tells you what's now collected

Discovery runs again every hour. What changed (new units, programs,
listeners, logs written but not collected) comes in its digest. It fixes and
narrows the interpreter on its own, and asks you before adding a source.

IAM for a finial is one permission: `s3:PutObject` on `PREFIX/*/host=HOST/*`
([examples/iam/finial.json](examples/iam/finial.json)).

## The interpreter

```json
{"sources": [
   {"name": "appsrv", "path": "/home/psadm2/psft/pt/8.60/appserv/HRDEV/LOGS/APPSRV_*.LOG", "service": "hr-app",
    "multiline": {"start": "^PSAPPSRV\\.\\d+ "}, "placeholders": [{"name": "sql", "pattern": "'[^']*'"}]},
   {"name": "pia", "path": "/home/psadm2/psft/pt/8.60/webserv/peoplesoft/servers/PIA/logs/PIA_weblogic.log",
    "multiline": {"start": "^####<"}, "level": {"pattern": "^####<[^>]*> <(\\w+)>", "map": {"error": "error", "warning": "warn"}},
    "timestamp": {"pattern": "^####<(\\w{3} \\d{1,2}, \\d{4} \\d{1,2}:\\d\\d:\\d\\d,\\d+ [AP]M)", "format": "%b %d, %Y %I:%M:%S,%f %p"}},
   {"name": "units", "journald": {"user": true, "units": ["psappsrv.service", "pia.service"]}}],
 "services": {"hr-app": {"version": {"file": "/home/psadm2/psft/pt/8.60/peopletools.properties", "pattern": "^toolsrelease=(\\S+)"},
                         "watch": ["/home/psadm2/psft/pt/8.60/appserv/HRDEV/psappsrv.cfg"]}}}
```

That's the kind of spec a reviewer writes. None of it ships in eaveswatch.
`interpret init` starts from generic placeholders (times, ids, addresses,
numbers, quoted strings) and levels, and the reviewer adds the rest:

| Field | What it does |
|---|---|
| `sources` | `path` (a glob, so date-rolled logs are followed) or `journald` (`user`, `units`, `identifiers`) |
| per source | `service`, `multiline.start`, `timestamp` (pattern + strptime format), `level` (pattern + map), `placeholders`, `drop`/`keep`, `raw` (archive redacted entries), `from_start` |
| `services` | `git` (a checkout's commit) or `version` (`file` + `pattern`), and `watch`: config files hashed (never read out); a change shows in the digest |
| top level | `placeholders`, `level`, `redact` (extra patterns), `watch`, `spike`, `warmup_minutes`, `max_template`, `max_samples` |

```sh
eaveswatch interpret init FILE      # the starter
eaveswatch interpret test FILE      # real recent lines through it: entries, templates, timestamps, slow patterns
eaveswatch interpret apply FILE --note "why"     # the next version, active on the eave's next tick
eaveswatch interpret show | rollback [N]
```

A source's first read starts from the end of what's already there. A file
that appears later, like tomorrow's `APPSRV_1115.LOG`, is read from its start.

## The store

A folder, or `s3://bucket/prefix`. Hive-style prefixes, so Athena and Glue can
query the archive as it is:

```
PREFIX/env=prod/kind=packets/dt=2026-11-14/hour=09/host=ps-hr-01/ps-hr-01_20261114T091502Z_7f3a.jsonl.gz
```

- **Time before host:** the ridge lists one hour across every host, and IAM
  can still hold each host to its own prefix (`*/host=web-3/*`).
- **The name stands alone:** host, UTC stamp (sorts as text), a random suffix.
- **Kinds:**
  - `packets`: templates, counts, samples, new and spiking
  - `inventory`: versions, watched-file hashes, units, the interpreter version, the spool
  - `flows`
  - `raw`: redacted entries of sources marked `raw`, which is the archive
  - `requests` and `answers`: asks
  - `check`: probes, which a lifecycle rule can expire
- **Nothing is lost when the store is away.** Every file is spooled to disk
  before the eave saves its place in the logs, then sent oldest first. Past
  `spool_max_mb` the oldest `raw` files go first, and the gap is reported
  once the store is back. Delivery is at least once.
- **Late files keep their hour.** Every `late_every` seconds the ridge looks
  back `late_hours`.
- No boto3: SigV4 is signed in the standard library. Credentials come from the
  environment, `~/.aws/credentials`, the ECS task role or the instance role.

## A fleet

Every host runs an eave ([examples/fleet/](examples/fleet/)): plumbing-only
config, with its interpreter in `STATE_DIR/interpreter`. The hub runs the ridge
sync loop with the store's credentials, and the reviewer hobkin has none:
`ridge watch` and every command it runs read and write only the ridge's data
folder. IAM: [examples/iam/eave.json](examples/iam/eave.json) and
[examples/iam/ridge.json](examples/iam/ridge.json). The ridge never gets
`kind=raw`.

## What the reviewer does

The chore's instructions (`CHORE_MD` in `eaveswatch.py`; `eaveswatch chore`
writes them out) cover setting up, keeping the interpreter right, and
reviewing:

- **The map** (`DATA/map/`): hosts (what runs, versions, watched hashes), edges
  (listeners and who talks to whom), templates (hosts, versions, totals).
- **The digest** says what changed:
  - new hosts, and hosts gone quiet
  - deploys
  - config changes and interpreter versions
  - what changed on the box (from discovery)
  - new connections
  - spiking and new templates
  - answers to its asks
- **Asks** go to an eave from a fixed menu, never a shell: `ask HOST lines FP`,
  `ask HOST inventory`, `ask HOST flows`.
- **A finding** needs evidence, a failure scenario, an action and a
  confidence. Without all four it's an observation. Before recording one, a
  brownie tries to knock it down; at most three are recorded per digest.
- **The ledger** (`DATA/findings.jsonl`) is append-only. The same category and
  location is the same finding (counted again, not duplicated), a dismissal
  needs a reason and isn't recorded again, and each finding carries its
  inputs and the charter version.

```sh
eaveswatch finding add < finding.json
eaveswatch finding list [--all]
eaveswatch finding status F-1a2b3c4d dismissed --why "behind the VPN only"
```

## Check a box

`eaveswatch --config FILE check`, as the service's user, tests exactly what
its role does:
- **eave:** writes under its own host and lists its asks
- **ridge:** lists and reads what it syncs
- **finial:** only writes

It also reports where the credentials came from, the clock against S3's, the
active interpreter, every source (globs, permissions, journald), every
service's version and the watched files. Then it shows a preview of recent
lines as templates, with how many values were redacted. Each failure says what
to change, and the exit code is 1 on any failure.

## Config

Plumbing only; what to collect is the interpreter's.

| Setting | Default | |
|---|---|---|
| `role` | `eave` | `eave`, `ridge` or `finial` |
| `env` | `prod` | the `env=` prefix |
| `host` | hostname | the `host=` prefix |
| `store` | | a folder, or `s3://bucket/prefix` |
| `region`, `endpoint` | `$AWS_REGION` | S3 region; an S3-compatible endpoint (path-style) |
| `state_dir` | `/var/lib/eaveswatch` | offsets, cursors, baselines, the spool; the ridge's data default |
| `interpreter` | | the interpreter folder; default `RIDGE_DATA/interpreter` for a finial (the reviewer writes it), else `STATE_DIR/interpreter` |
| `every` | `60` | seconds between ticks |
| `inventory_every` | `3600` | inventory and flows: on change, and at least this often |
| `discover_every` | `3600` | a finial's look at what runs here |
| `spool_max_mb` | `512` | the most kept waiting for the store |
| `ridge` | | `data`, `envs`, `silent_after`, `late_hours` (`24`), `late_every` (`600`) |

## Tests

`python3 tests/test_eaveswatch.py`. No AWS and no cost. It covers:
- the redaction floor
- the interpreter: validation, credentials refused, multi-line WebLogic
  records, levels, timestamps, a catastrophic pattern caught
- discovery of a real process here: its open log and its port
- date-rolled logs
- versions and watched files
- the layout and AWS's own SigV4 test vector
- full round trips on a folder, a fake S3 that checks every signature, and a finial
- the spool through an outage
- check, the ledger and the chore
