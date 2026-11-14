# Working on eaveswatch

- **One file, standard library only:** `eaveswatch.py`, Python 3.9+. No third-party packages (no boto3:
  SigV4 is signed by hand), no listening ports, no build step. `grep -n '^# ----' eaveswatch.py` lists its
  sections; new code goes in the section it belongs to, and the map at the top stays in step.
- **Same module everywhere:** roles (`eave`, `ridge`, `finial`) are config, not forks. A ridge can be an eave
  of a bigger ridge; keep that true.
- **No baked-in log rules.** What to collect and how to read it is the interpreter spec (data, written by the
  reviewer from `discover` and its human, checked by `interpret test`). The code runs patterns; it never runs code
  from a spec. The starter spec is a starting point, not a rule set. Config stays plumbing only.
- **The redaction floor (`REDACT`) and the credential deny-list (`DENY_PATHS`, `DENY_NAMES`) are the exception:**
  always on, and a spec can only add to them. Never make either configurable away.
- **The store layout is a contract** (Athena tables and IAM policies are written against it):
  `PREFIX/env=/kind=/dt=YYYY-MM-DD/hour=HH/host=/HOST_STAMP_RAND.jsonl.gz`, gzipped JSON lines. Change it only
  on purpose, with the README. Systems' shared state lives beside it at `PREFIX/systems/system=NAME/`.
- **Nothing leaves a host unredacted.** Redaction runs before templating, samples, raw, answers and discovery
  samples. A new output path goes through the interpreter's `redact` too. Discovery lists config files, never
  reads them out; watched files are hashed, never sent.
- **The reviewer has no credentials and no network.** `ridge sync` (the plain loop) talks to the store;
  `ridge watch` and everything the hobkin runs read and write only the ridge's data folder. Asks to eaves are
  a fixed menu (`lines`, `inventory`, `flows`): never add one that runs a command it's given.
- **Nodes can drop out at any moment.** What a system knows lives in its shared state in the store, never only
  on one node. Writes that two nodes could make at once are conditional (create-if-absent, update-if-unchanged:
  `Conflict`), or one object per event (the ledger) so nothing is overwritten. The ridge is a lease, not a box;
  review jobs go to the host their evidence came from, and claims run out when a node dies. Test any change
  with nodes that stop mid-way.
- **People are reached through one queue** (`DATA/notify/queue/`), sent by the plain loop (sendmail or SMTP,
  capped per hour): fired alerts, the reviewer's notes, hobkin's own alerts. The reviewer only writes the queue
  (it has no network). Alert rules are spec data checked by plain code each tick, never a model call.
- **The findings page is static HTML** written by the loop to `DATA/report/` and an optional publish folder that
  another server already serves. eaveswatch itself serves nothing. Escape everything in it: it shows log text.
- **Quiet is free:** `ridge watch` prints nothing when there's nothing new, so a hobkin's wake costs no model
  call. Don't make it chatty.
- **The reviewer's instructions** are a hobkin chore kept inside the file (`CHORE_JSON`, `CHORE_MD`), so a
  pip install carries it; `eaveswatch chore` writes it out where hobkin finds chores by name.
- **No auto-updates or migrations:** no code that detects an older state file or layout and rewrites it.
- **Tests:** `python3 tests/test_eaveswatch.py` (folder store and a fake S3; no AWS). Add a check for what you
  change; run what you changed, CI runs the rest.
- GitHub: `frank-lynam/hobkin-eaveswatch` (remote `origin` uses the `github-hobkin-eaveswatch` SSH alias).
  Commit and push finished work. PyPI name `hobkin-eaveswatch`: don't publish without asking.
