# Working on eaveswatch

- **One file, standard library only:** `eaveswatch.py`, Python 3.9+. No third-party packages (no boto3:
  SigV4 is signed by hand), no listening ports, no build step. `grep -n '^# ----' eaveswatch.py` lists its
  sections; new code goes in the section it belongs to, and the map at the top stays in step.
- **Same module everywhere:** roles (`eave`, `ridge`, `local`) are config, not forks. A ridge can be an eave
  of a bigger ridge; keep that true.
- **The store layout is a contract** (Athena tables and IAM policies are written against it):
  `PREFIX/env=/kind=/dt=YYYY-MM-DD/hour=HH/host=/HOST_STAMP_RAND.jsonl.gz`, gzipped JSON lines. Change it only
  on purpose, with the README.
- **Nothing leaves a host unredacted.** Redaction runs before templating, samples, raw and answers. A new
  output path goes through `self.redact` too.
- **The reviewer has no credentials and no network.** `ridge sync` (the plain loop) talks to the store;
  `ridge watch` and everything the hobkin runs read and write only the ridge's data folder. Asks to eaves are
  a fixed menu (`lines`, `inventory`, `flows`): never add one that runs a command it's given.
- **Quiet is free:** `ridge watch` prints nothing when there's nothing new, so a hobkin's wake costs no model
  call. Don't make it chatty.
- **The reviewer's instructions** are `chore/eaveswatch/` (a hobkin chore: `chore.json`, `CHORE.md`).
- **No auto-updates or migrations:** no code that detects an older state file or layout and rewrites it.
- **Tests:** `python3 tests/test_eaveswatch.py` (folder store and a fake S3; no AWS). Add a check for what you
  change; run what you changed, CI runs the rest.
- GitHub: `frank-lynam/hobkin-eaveswatch` (remote `origin` uses the `github-hobkin-eaveswatch` SSH alias).
  Commit and push finished work. PyPI name `hobkin-eaveswatch`: don't publish without asking.
