"""Tests for eaveswatch: the text helpers, the layout, SigV4, and an eave -> store -> ridge round trip on a
folder store and on a fake S3 (no AWS, no cost).

    python3 tests/test_eaveswatch.py
"""
import gzip, hashlib, http.server, io, json, os, re, subprocess, sys, tempfile, threading, time, urllib.parse
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import eaveswatch as ew

FAILED = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {str(detail)[:600]}"), flush=True)
    if not ok:
        FAILED.append(name)


# ---- text
r = ew.redactor([r"cust-\d{6}"])
for raw, want in [("GET /x?token=abc123&u=1", "GET /x?token=<redacted>&u=1"),
                  ('password="hunter2" ok', 'password="<redacted>" ok'),
                  ("key AKIAABCDEFGHIJKLMNOP here", "key <redacted> here"),
                  ("https://bob:pw@db.local/x", "https://bob:<redacted>@db.local/x"),
                  ("api_key: sk-live-123 for cust-123456", "api_key: <redacted> for <redacted>"),
                  ("jwt eyJhbGciOiJI.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "jwt <redacted>")]:
    check(f"[text] redacts: {raw}", r(raw) == want, r(raw))
t = ew.template('2026-11-14T09:15:02Z ERROR user 4f2a9c1b-1111-2222-3333-444455556666 from 10.0.3.4:5532 took 532ms "GET /a" id=0xdeadbeef9')
check("[text] a template keeps the words and drops what varies",
      t == '<ts> ERROR user <uuid> from <ip> took <n> "<str>" id=<hex>', t)
check("[text] terminal colours and escapes are dropped, long mixed ids are placeholders",
      ew.template("\x1b[32mok\x1b[0m \x1b]8;;https://x\x07link\x1b]8;;\x07 session_01U5HvRjSMeaGk45FYMcmCk4 done")
      == "ok link <id> done", ew.template("\x1b[32mok\x1b[0m \x1b]8;;https://x\x07link\x1b]8;;\x07 session_01U5HvRjSMeaGk45FYMcmCk4 done"))
check("[text] the same shape is the same fingerprint, per source",
      ew.fingerprint("api", ew.template("took 5ms")) == ew.fingerprint("api", ew.template("took 900ms"))
      and ew.fingerprint("api", "x") != ew.fingerprint("web", "x"))
check("[text] levels from words, or journald's priority",
      ew.level_of("an ERROR here") == "error" and ew.level_of("x", "4") == "warn" and ew.level_of("plain") is None
      and ew.level_of("ERROR at the default priority", "6") == "error")
check("[flows] a client's UDP socket on an ephemeral port isn't a listener",
      [l["port"] for l in ew.parse_ss("udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:41826 0.0.0.0:*", "h")["listening"]] == [5353])

# ---- layout
k = ew.object_key("prod", "packets", "web-3", ew.parse_iso("2026-11-14T09:15:02Z"))
check("[layout] Hive-style prefixes, time then host, host and UTC stamp in the name",
      re.fullmatch(r"env=prod/kind=packets/dt=2026-11-14/hour=09/host=web-3/web-3_20261114T091502Z_[0-9a-f]{4}\.jsonl\.gz", k), k)
check("[layout] host names are made safe for a key", ew.safe_name("web 3/../x") == "web-3-..-x")

# ---- SigV4: AWS's own test vector (get-vanilla)
auth = ew.sign_v4("GET", "example.amazonaws.com", "/", {}, {"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"},
                  hashlib.sha256(b"").hexdigest(), "us-east-1", "service", "AKIDEXAMPLE",
                  "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830T123600Z")
check("[s3] SigV4 matches AWS's get-vanilla test vector",
      auth.endswith("Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"), auth)

# ---- versions
g = tempfile.mkdtemp(prefix="eaveswatch-git-")
os.makedirs(os.path.join(g, ".git", "refs", "heads"))
open(os.path.join(g, ".git", "HEAD"), "w").write("ref: refs/heads/main\n")
open(os.path.join(g, ".git", "packed-refs"), "w").write("# pack-refs\n" + "ab" * 20 + " refs/heads/main\n")
check("[versions] a checkout's commit, even where git won't run (read from .git, packed refs too)",
      ew.git_head(g) == "ab" * 20, ew.git_head(g))
own = subprocess.run(["git", "-C", os.path.join(HERE, ".."), "rev-parse", "HEAD"], capture_output=True, text=True)
if own.returncode == 0:                  # a checkout with a commit (not a fresh repo, or an sdist)
    check("[versions] this repo's own commit, through git", ew.git_head(os.path.join(HERE, "..")) == own.stdout.strip())

# ---- flows
ss = """tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1,fd=6))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=2,fd=3))
tcp ESTAB 0 0 10.0.0.5:443 10.0.9.9:51544 users:(("nginx",pid=1,fd=7))
tcp ESTAB 0 0 10.0.0.5:443 10.0.9.9:51545 users:(("nginx",pid=1,fd=8))
tcp ESTAB 0 0 10.0.0.5:40112 10.0.1.20:5432 users:(("api",pid=3,fd=9))
tcp ESTAB 0 0 127.0.0.1:40000 127.0.0.1:6379
"""
fl = ew.parse_ss(ss, "web-3")
check("[flows] listeners, inbound folded by port, outbound by peer port, loopback left out",
      [l["port"] for l in fl["listening"]] == [22, 443]
      and fl["edges"] == [{"dir": "in", "proto": "tcp", "peer": "10.0.9.9", "port": 443, "process": "nginx", "count": 2},
                          {"dir": "out", "proto": "tcp", "peer": "10.0.1.20", "port": 5432, "process": "api", "count": 1}], fl)


# ---- a round trip: two eaves -> a store -> the ridge
def setup(store):
    base = tempfile.mkdtemp(prefix="eaveswatch-test-")
    logs = os.path.join(base, "logs")
    os.makedirs(logs)
    cfgs = {}
    for host in ("web-1", "web-2"):
        open(os.path.join(logs, f"{host}.log"), "w").close()
        cfgs[host] = {**ew.DEFAULTS, "store": store, "env": "test", "host": host, "state_dir": os.path.join(base, host),
                      "warmup_minutes": 0, "sources": [{"name": "app", "path": os.path.join(logs, f"{host}.log"), "from_start": True,
                                                       "service": "api"}],
                      "raw": ["app"], "services": {"api": {"version_file": os.path.join(base, "VERSION")}},
                      "ridge": {**ew.DEFAULTS["ridge"], "data": os.path.join(base, "ridge")}}
    open(os.path.join(base, "VERSION"), "w").write("abc123def456")
    return base, logs, cfgs


def write(path, lines):
    with open(path, "a") as f:
        f.write("".join(l + "\n" for l in lines))


def round_trip(label, store_url, store_obj=None):
    base, logs, cfgs = setup(store_url)
    eaves = {h: ew.Eave(c, store_obj) for h, c in cfgs.items()}
    for e in eaves.values():
        e.state["started"] = "2020-01-01T00:00:00Z"          # past its warm-up
    write(f"{logs}/web-1.log", ["INFO request ok in 12ms", "INFO request ok in 15ms", "WARN slow query 900ms password=hunter2"])
    write(f"{logs}/web-2.log", ["INFO request ok in 9ms"])
    keys = eaves["web-1"].tick() + eaves["web-2"].tick()
    kinds = sorted({re.search(r"kind=(\w+)", k).group(1) for k in keys})
    check(f"[{label}] a tick writes packets, raw, inventory and flows", kinds == ["flows", "inventory", "packets", "raw"], keys)
    store = store_obj or ew.open_store(cfgs["web-1"])
    pk = [k for k in keys if "kind=packets" in k and "host=web-1" in k][0]
    recs = ew.unpack(store.get(pk))
    by = {x["template"]: x for x in recs}
    ok_rec = by.get("INFO request ok in <n>", {})
    check(f"[{label}] packets: templates counted, samples redacted, the version of the code that wrote them",
          ok_rec.get("count") == 2 and ok_rec.get("version") == "abc123def456" and ok_rec.get("service") == "api"
          and "hunter2" not in json.dumps(recs) and "password=<redacted>" in json.dumps(recs), recs)
    raw = [k for k in keys if "kind=raw" in k and "host=web-1" in k]
    check(f"[{label}] raw archive (opt-in) is redacted too", raw and "hunter2" not in gzip.decompress(store.get(raw[0])).decode())
    # second tick: a spike and a new template
    write(f"{logs}/web-1.log", ["INFO request ok in 3ms"] * 30 + ["ERROR db connection refused to 10.0.1.20:5432"])
    keys2 = eaves["web-1"].tick()
    recs2 = {x["template"]: x for x in ew.unpack(store.get([k for k in keys2 if "kind=packets" in k][0]))}
    check(f"[{label}] a spike and a new template are flagged at the eave",
          recs2["INFO request ok in <n>"]["spike"] and recs2["ERROR db connection refused to <ip>"]["new"], recs2)
    check(f"[{label}] unchanged inventory and flows aren't sent again", not [k for k in keys2 if "kind=inventory" in k], keys2)
    # the ridge
    ridge = ew.Ridge(cfgs["web-1"], store_obj)
    got = ridge.sync()
    check(f"[{label}] ridge sync pulls everything but raw", got == len([k for k in keys + keys2 if "kind=raw" not in k]), got)
    check(f"[{label}] a second sync finds nothing new", ridge.sync() == 0)
    digest = ridge.watch()
    check(f"[{label}] the digest: new hosts, the spike, the new template (with its fp and version), saved",
          "## New hosts" in digest and "web-1" in digest and "web-2" in digest and "## Spiking log templates" in digest
          and "ERROR db connection refused to <ip>" in digest and "abc123def456"[:12] in digest
          and os.listdir(os.path.join(base, "ridge", "digests")), digest[:1500])
    check(f"[{label}] watch is silent with nothing new", ridge.watch() == "")
    hosts = json.load(open(os.path.join(base, "ridge", "map", "hosts.json")))
    check(f"[{label}] the map knows each host and its versions", sorted(hosts) == ["web-1", "web-2"]
          and hosts["web-1"]["services"] == {"api": "abc123def456"}, hosts)
    # a deploy shows as a version change
    open(os.path.join(base, "VERSION"), "w").write("fff999")
    eaves["web-2"].tick()
    ridge.sync()
    d2 = ridge.watch()
    check(f"[{label}] a deploy shows in the digest", "## Deploys" in d2 and "web-2 api: abc123def456 -> fff999" in d2, d2)
    # an ask: ridge -> outbox -> store -> eave answers -> ridge
    fp = recs2["ERROR db connection refused to <ip>"]["fp"]
    ridge.ask("web-1", "lines", fp=fp)
    ridge.sync()
    eaves["web-1"].tick()
    ridge.sync()
    d3 = ridge.watch()
    ans_files = [os.path.join(d, n) for d, _, ns in os.walk(os.path.join(base, "ridge", "answers")) for n in ns]
    ans = json.loads(open(ans_files[0]).read().split("\n}\n")[0] + "\n}") if ans_files else {}
    check(f"[{label}] an ask is answered from the eave's own logs, redacted, and shows in the digest",
          "## Answers to your asks" in d3 and ans.get("lines") == ["ERROR db connection refused to 10.0.1.20:5432"], (d3, ans))
    return base, cfgs


base, cfgs = round_trip("folder", None or tempfile.mkdtemp(prefix="eaveswatch-store-"))


# ---- a fake S3 (path-style), checking each request is signed for the URL it was sent to
class FakeS3(http.server.BaseHTTPRequestHandler):
    objects = {}
    bad = []

    def log_message(self, *a):
        pass

    def verify(self, body=b""):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        h = {k: self.headers[k] for k in ("host", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token") if self.headers.get(k)}
        want = ew.sign_v4(self.command, h["host"], u.path, q, h, hashlib.sha256(body).hexdigest(), "us-east-1", "s3",
                          "AKIDTEST", "secret", h["x-amz-date"])
        if self.headers.get("Authorization") != want:
            FakeS3.bad.append(self.path)

    deny_put = False

    def do_PUT(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        self.verify(body)
        if FakeS3.deny_put:
            err = b"<?xml version='1.0'?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
            self.send_response(403); self.send_header("content-length", str(len(err))); self.end_headers(); self.wfile.write(err)
            return
        FakeS3.objects[urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)] = body
        self.send_response(200); self.end_headers()

    def do_GET(self):
        self.verify()
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if q.get("list-type") == "2":
            bucket = u.path.strip("/")
            pre = f"/{bucket}/" + q.get("prefix", "")
            keys = sorted(k[len(bucket) + 2:] for k in FakeS3.objects if k.startswith(pre))
            start = int(q.get("continuation-token") or 0)
            page, more = keys[start:start + 3], start + 3 < len(keys)       # small pages: paging gets tested
            body = ('<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                    + "".join(f"<Contents><Key>{k}</Key></Contents>" for k in page)
                    + f"<IsTruncated>{'true' if more else 'false'}</IsTruncated>"
                    + (f"<NextContinuationToken>{start + 3}</NextContinuationToken>" if more else "") + "</ListBucketResult>").encode()
        else:
            body = FakeS3.objects.get(urllib.parse.unquote(u.path))
            if body is None:
                self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeS3)
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ.update(AWS_ACCESS_KEY_ID="AKIDTEST", AWS_SECRET_ACCESS_KEY="secret", AWS_REGION="us-east-1")
os.environ.pop("AWS_SESSION_TOKEN", None)
s3 = ew.S3Store("s3://bucket/eaves/v1", endpoint=f"http://127.0.0.1:{srv.server_port}")
round_trip("s3", "s3://bucket/eaves/v1", s3)
check("[s3] every request's signature matches the URL it went to (prefixes with / and = included)", not FakeS3.bad, FakeS3.bad[:3])
s3cfg = {**ew.DEFAULTS, "store": "s3://bucket/eaves/v1", "env": "test", "host": "web-7", "role": "eave",
         "state_dir": tempfile.mkdtemp(prefix="eaveswatch-check-"), "sources": [], "ridge": dict(ew.DEFAULTS["ridge"], data=None)}
s3cfg["ridge"]["data"] = os.path.join(s3cfg["state_dir"], "ridge")
text, problems = ew.run_check(s3cfg, "test.json", s3)
check("[check] an eave on S3: where its credentials came from (key masked), a probe under its own host, its asks, the clock",
      problems == 0 and "credentials: environment (AWS_ACCESS_KEY_ID) (key AKID…TEST)" in text
      and "store: write: env=test/kind=check/" in text and "host=web-7/" in text and "list asks" in text
      and re.search(r"ok    clock: \d+s", text) and "secret" not in text, text)
FakeS3.deny_put = True
text, problems = ew.run_check(s3cfg, "test.json", ew.S3Store("s3://bucket/eaves/v1", endpoint=f"http://127.0.0.1:{srv.server_port}"))
FakeS3.deny_put = False
check("[check] S3 refusing says S3's own reason and the permission to add",
      problems == 1 and "FAIL  store: write: 403 AccessDenied: Access Denied" in text
      and "fix: allow s3:PutObject on s3://bucket/eaves/v1/*/host=web-7/*" in text, text)
rd_text, rd_problems = ew.run_check({**s3cfg, "role": "ridge"}, "test.json", s3)
check("[check] a ridge on S3: lists and reads each kind it syncs", rd_problems == 0
      and all(f"test/{k}" in rd_text for k in ("packets", "inventory", "flows", "answers")), rd_text)
check("[s3] objects land under the bucket's prefix", all(k.startswith("/bucket/eaves/v1/env=test/kind=") for k in FakeS3.objects),
      list(FakeS3.objects)[:3])

# ---- the spool: a store that's down loses nothing; a full spool drops raw first, and says so
class Flaky(ew.FolderStore):
    down = False

    def put(self, key, data):
        if self.down:
            raise urllib.error.URLError("store unreachable")
        super().put(key, data)

    def list(self, prefix):
        if self.down:
            raise urllib.error.URLError("store unreachable")
        return super().list(prefix)


import urllib.error
sbase, slogs, scfgs = setup(tempfile.mkdtemp(prefix="eaveswatch-flaky-"))
flaky = Flaky(scfgs["web-1"]["store"])
ev = ew.Eave(scfgs["web-1"], flaky)
ev.state["started"] = "2020-01-01T00:00:00Z"
flaky.down = True
write(f"{slogs}/web-1.log", ["INFO job done in 5ms"] * 7)
k1 = ev.tick()
write(f"{slogs}/web-1.log", ["INFO job done in 6ms"] * 5)
k2 = ev.tick()
check("[spool] with the store down, ticks spool their files, save their place, and say why",
      ev.last_flush == (0, len(k1) + len(k2)) and not flaky.list.__func__ is None and "store unreachable" in ev.state["spool_error"]
      and json.load(open(os.path.join(scfgs["web-1"]["state_dir"], "eave.json")))["files"], (ev.last_flush, k1, k2))
flaky.down = False
ev.tick()
check("[spool] back up: everything is sent, oldest first, and the spool empties",
      ev.spooled() == [] and "spool_error" not in ev.state and ev.last_flush[1] == 0, ev.spooled())
rd = ew.Ridge(scfgs["web-1"], flaky)
rd.sync()
counted = sum(r["count"] for d, _, ns in os.walk(os.path.join(scfgs["web-1"]["ridge"]["data"], "inbox")) for n in ns
              if "kind=packets" in d for r in ew.unpack(open(os.path.join(d, n), "rb").read()) if r["template"] == "INFO job done in <n>")
check("[spool] no line lost across the outage", counted == 12, counted)
inv = [r for d, _, ns in os.walk(os.path.join(scfgs["web-1"]["ridge"]["data"], "inbox")) for n in ns if "kind=inventory" in d
       for r in ew.unpack(open(os.path.join(d, n), "rb").read())]
check("[spool] inventory reports the spool (files, oldest, dropped, last error)",
      inv and set(inv[0]["spool"]) == {"files", "bytes", "oldest", "dropped", "last_error"}, inv[:1])

scfgs["web-2"]["spool_max_mb"] = 0.002                  # about 2 KB
ev2 = ew.Eave(scfgs["web-2"], flaky)
ev2.state["started"] = "2020-01-01T00:00:00Z"
flaky.down = True
for i in range(4):
    write(f"{slogs}/web-2.log", [f"WARN cache miss key-{i}-{j} {'x' * 200}" for j in range(20)])
    ev2.tick()
kinds_left = [k for _, k, _ in ev2.spooled()]
check("[spool] over its cap, the oldest raw files go first",
      ev2.state.get("spool_dropped", 0) > 0 and sum(b for _, _, b in ev2.spooled()) <= 0.002 * 1024 * 1024
      and any("kind=packets" in k for k in kinds_left), (ev2.state.get("spool_dropped"), kinds_left))
flaky.down = False
ev2.tick()
gap = [r for k in flaky.list("env=test/kind=packets/") if "host=web-2" in k for r in ew.unpack(flaky.get(k))
       if r["source"] == "eaveswatch"]
check("[spool] what was dropped is reported once, as an error the ridge will see, once the store's back",
      len(gap) == 1 and gap[0]["level"] == "error" and gap[0]["count"] == ev2.state["spool_dropped"]
      and "store unreachable" in gap[0]["samples"][0] and "spool_dropped_new" not in ev2.state, gap)

# late arrivals: a file for an hour the ridge has passed is found by the next look back
rd.sync(deep=True)
late = ew.object_key("test", "packets", "web-9", ew.now_utc() - ew.dt.timedelta(hours=5))
flaky.put(late, ew.pack([{"fp": "late1", "template": "late", "count": 1, "host": "web-9", "window": ["", ""]}]))
check("[ridge] a late file for an old hour waits for the look back, then arrives once",
      rd.sync(deep=False) == 0 and rd.sync(deep=True) == 1 and rd.sync(deep=True) == 0)
rd.watch()
check("[ridge] fetched files are remembered by the data folder itself (archived ones too)",
      rd.have(late) and rd.sync(deep=True) == 0)

# ---- check on a folder store: a good eave, then the usual mistakes
cbase, clogs, ccfgs = setup(tempfile.mkdtemp(prefix="eaveswatch-check-store-"))
good_cfg = ccfgs["web-1"]
write(f"{clogs}/web-1.log", ["INFO request ok in 12ms token=abc123secret", "INFO request ok in 15ms"])
text, problems = ew.run_check(good_cfg, "good.json")
check("[check] a good eave: all ok, a preview of its templates, redaction counted, nothing sent but the probe",
      problems == 0 and "all good" in text and "1x  [app] INFO request ok in <n>\n" in text
      and "1x  [app] INFO request ok in <n> token=<redacted>" in text and "1 values redacted" in text
      and "abc123secret" not in text and not [k for k in ew.FolderStore(good_cfg["store"]).list("") if "kind=check" not in k], text)
bad = {**good_cfg, "sources": good_cfg["sources"] + [{"name": "nginx", "path": "/nonexistent/*.log"},
                                                     {"name": "odd"}, {"name": "db", "path": f"{clogs}/web-1.log", "service": "db"}],
       "services": {**good_cfg["services"], "worker": {"dir": "/nonexistent"}}}
text, problems = ew.run_check(bad, "bad.json")
check("[check] the usual mistakes, each with its fix: a glob matching nothing, a source with no path, "
      "a service that isn't a checkout, a source tied to an unknown service",
      problems == 4 and "FAIL  source nginx: /nonexistent/*.log matches no files" in text
      and "FAIL  source odd: has neither a path nor journald" in text and "FAIL  service worker: no version" in text
      and "FAIL  service db: a source names it" in text and text.count("fix: ") == 4 and text.endswith("4 problems"), text)

# ---- findings
cfg = cfgs["web-1"]
good = {"category": "security/authz", "location": "api src/auth.py:88", "claim": "c", "evidence": "e", "scenario": "s",
        "action": "a", "confidence": "medium"}
try:
    ew.finding_add(cfg, {**good, "scenario": ""})
    check("[findings] one missing a scenario is refused", False)
except ValueError as e:
    check("[findings] one missing a scenario is refused (an observation, not a finding)", "scenario" in str(e), e)
first = ew.finding_add(cfg, good)
again = ew.finding_add(cfg, {**good, "evidence": "more"})
fid = first.split()[0]
check("[findings] recorded once, then counted as seen again", first.endswith("recorded") and "seen again (now 2 times)" in again,
      (first, again))
try:
    ew.finding_status(cfg, fid, "dismissed", None)
    check("[findings] a dismissal without a reason is refused", False)
except ValueError:
    check("[findings] a dismissal without a reason is refused", True)
ew.finding_status(cfg, fid, "dismissed", "behind the VPN only")
check("[findings] a dismissed one isn't recorded again", "was dismissed (behind the VPN only)" in ew.finding_add(cfg, good))
f = ew.findings(cfg)[fid]
check("[findings] its state is its events folded: status, sightings, history",
      f["status"] == "dismissed" and f["sightings"] == 2 and [h["event"] for h in f["history"]] == ["new", "seen", "status"], f)

# ---- the command line
cfg_path = os.path.join(base, "eaveswatch.json")
json.dump({"store": os.path.join(base, "store"), "env": "test", "state_dir": os.path.join(base, "cli"), "host": "cli-1"}, open(cfg_path, "w"))
out = subprocess.run([sys.executable, os.path.join(HERE, "..", "eaveswatch.py"), "--config", cfg_path, "key", "flows"],
                     capture_output=True, text=True)
check("[cli] key prints where a file would go", re.match(r"env=test/kind=flows/dt=\d{4}-\d\d-\d\d/hour=\d\d/host=cli-1/cli-1_", out.stdout),
      out.stdout + out.stderr)
out = subprocess.run([sys.executable, os.path.join(HERE, "..", "eaveswatch.py"), "--config", cfg_path, "ridge", "watch"],
                     capture_output=True, text=True)
chk = subprocess.run([sys.executable, os.path.join(HERE, "..", "eaveswatch.py"), "--config", cfg_path, "check"],
                     capture_output=True, text=True)
json.dump({"store": os.path.join(base, "store"), "state_dir": os.path.join(base, "cli"), "host": "cli-1",
           "sources": [{"name": "x", "path": "/nonexistent/*"}]}, open(cfg_path + ".bad", "w"))
bad_chk = subprocess.run([sys.executable, os.path.join(HERE, "..", "eaveswatch.py"), "--config", cfg_path + ".bad", "check"],
                         capture_output=True, text=True)
check("[cli] check exits 0 when all's well, 1 with a problem (for scripts and deploys)",
      chk.returncode == 0 and "all good" in chk.stdout and bad_chk.returncode == 1 and "1 problem" in bad_chk.stdout,
      chk.stdout[-300:] + bad_chk.stdout[-300:])
check("[cli] ridge watch with nothing new prints nothing (a quiet wake)", out.returncode == 0 and out.stdout == "", out.stdout + out.stderr)

chores = tempfile.mkdtemp(prefix="eaveswatch-chores-")
out = subprocess.run([sys.executable, os.path.join(HERE, "..", "eaveswatch.py"), "chore", chores], capture_output=True, text=True)
cj = json.load(open(os.path.join(chores, "eaveswatch", "chore.json"))) if out.returncode == 0 else {}
check("[chore] eaveswatch chore writes the reviewer chore (no config needed): a quiet watch, safe mode writing only data",
      cj.get("name") == "eaveswatch" and cj["config"]["wake"]["command"] == "eaveswatch --config {{config}} ridge watch"
      and cj["config"]["safe_mode"] == {"write": ["{{data}}"]}
      and "## The bar for a finding" in open(os.path.join(chores, "eaveswatch", "CHORE.md")).read(), out.stdout + out.stderr)
again = subprocess.run([sys.executable, os.path.join(HERE, "..", "eaveswatch.py"), "chore", chores], capture_output=True, text=True)
check("[chore] an installed chore isn't replaced without --force", again.returncode != 0 and "--force" in again.stderr, again.stderr)

print("\nALL PASSED" if not FAILED else f"\nFAILED: {len(FAILED)}")
sys.exit(1 if FAILED else 0)
