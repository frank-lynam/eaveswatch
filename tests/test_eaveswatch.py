"""Tests for eaveswatch: the redaction floor, the interpreter (validation, multiline, placeholders, levels,
timestamps, versions), discovery on this machine, the layout, SigV4, and eave -> store -> ridge round trips on a
folder store, a fake S3, and a finial (no AWS, no cost).

    python3 tests/test_eaveswatch.py
"""
import gzip, hashlib, http.server, json, os, re, subprocess, sys, tempfile, threading, time, urllib.error, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
EW = os.path.join(HERE, "..", "eaveswatch.py")
sys.path.insert(0, os.path.join(HERE, ".."))
import eaveswatch as ew

FAILED = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {str(detail)[:900]}"), flush=True)
    if not ok:
        FAILED.append(name)


def write(path, lines):
    with open(path, "a") as f:
        f.write("".join(l + "\n" for l in lines))


def cli(*args, stdin=None):
    return subprocess.run([sys.executable, EW] + list(args), capture_output=True, text=True, input=stdin)


def spec_file(spec, where):
    p = os.path.join(where, f"spec_{len(os.listdir(where))}.json")
    json.dump(spec, open(p, "w"))
    return p


# ---- the redaction floor
r = ew.redactor([r"cust-\d{6}"])
for raw, want in [("GET /x?token=abc123&u=1", "GET /x?token=<redacted>&u=1"),
                  ('password="hunter2" ok', 'password="<redacted>" ok'),
                  ("key AKIAABCDEFGHIJKLMNOP here", "key <redacted> here"),
                  ("https://bob:pw@db.local/x", "https://bob:<redacted>@db.local/x"),
                  ("api_key: sk-live-123 for cust-123456", "api_key: <redacted> for <redacted>"),
                  ("jwt eyJhbGciOiJI.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "jwt <redacted>"),
                  ("Cookie: PS_TOKEN=qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AcQg4AC4AMQAwABQ; JSESSIONID=x9f2Kk",
                   "Cookie: PS_TOKEN=<redacted>; JSESSIONID=<redacted>"),
                  ("blob MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7 end", "blob <redacted blob> end")]:
    check(f"[floor] redacts: {raw[:60]}", r(raw) == want, r(raw))

# ---- the interpreter: the starter, validation, what a spec can't do
it = ew.Interpreter(ew.STARTER_SPEC)
t = it.template('2026-11-14T09:15:02Z ERROR user 4f2a9c1b-1111-2222-3333-444455556666 from 10.0.3.4:5532 took 532ms "GET /a" id=0xdeadbeef9')
check("[interp] the starter spec's placeholders keep the words and drop what varies",
      t == '<ts> ERROR user <uuid> from <ip> took <n> "<str>" id=<hex>', t)
check("[interp] terminal escapes are dropped, long mixed ids are placeholders",
      it.template("\x1b[32mok\x1b[0m \x1b]8;;https://x\x07link\x1b]8;;\x07 session_01U5HvRjSMeaGk45FYMcmCk4 done") == "ok link <id> done")
check("[interp] levels from the words, or journald's priority, whichever is worse",
      it.level("an ERROR here") == "error" and it.level("x", "4") == "warn" and it.level("plain") is None
      and it.level("ERROR at the default priority", "6") == "error" and it.level("<Sev> SEVERE x") == "error")
check("[interp] the same shape is the same fingerprint, per source",
      ew.fingerprint("api", it.template("took 5ms")) == ew.fingerprint("api", it.template("took 900ms"))
      and ew.fingerprint("api", "x") != ew.fingerprint("web", "x"))
tmp = tempfile.mkdtemp(prefix="eaveswatch-spec-")
open(os.path.join(tmp, "server.key"), "w").write("x")
open(os.path.join(tmp, "token-service.log"), "w").write("x\n")
errs = ew.validate_spec({"sources": [
    {"name": "a", "path": "/x/*.log", "multiline": {"start": "([unclosed"}},
    {"name": "a", "path": "/y/*.log"},
    {"name": "b", "path": "/z.log", "journald": {"user": True}},
    {"name": "c", "path": "~/.ssh/*"},
    {"name": "d", "path": os.path.join(tmp, "server.key")},
    {"name": "e", "path": "/q.log", "service": "nope", "colour": "red"},
    {"name": "f", "path": "/r.log", "timestamp": {"pattern": "\\d+"}}],
    "level": {"pattern": "(x)", "map": {"x": "loud"}}, "bogus": 1})
want_bits = ["bad regex", "used twice", "exactly one of", "~/.ssh", "credential file", "service 'nope'", "colour: not a setting",
             "needs a (group)", "needs a strptime", "level.map", "bogus: not a setting"]
check("[interp] validation lists every problem at once: bad regexes, duplicates, credentials, unknown keys...",
      all(any(b in e for e in errs) for b in want_bits), errs)
check("[interp] a log whose name says token is still a log; a key file isn't",
      ew.denied(os.path.join(tmp, "token-service.log")) is None and ew.denied(os.path.join(tmp, "server.key")))

# multiline (a WebLogic record with a stack trace), the source's own level, timestamp and placeholders
wl = {"name": "pia", "path": "/x", "multiline": {"start": "^####<"},
      "level": {"pattern": r"^####<[^>]*> <(\w+)>", "map": {"error": "error", "warning": "warn", "info": "info", "notice": "info"}},
      "timestamp": {"pattern": r"^####<(\w{3} \d{1,2}, \d{4} \d{1,2}:\d{2}:\d{2},\d+ [AP]M)", "format": "%b %d, %Y %I:%M:%S,%f %p"},
      "placeholders": [{"name": "epoch", "pattern": r"\b\d{13}\b"}, {"name": "thread", "pattern": r"ExecuteThread: '\d+'"}],
      "drop": [r"<Debug>"]}
wit = ew.Interpreter({"sources": [wl]})
src = wit.source("pia")
lines = []
for n, (tm, th, ep) in enumerate([("9:15:02,123 AM", 3, 1731593702123), ("10:01:44,9 AM", 11, 1731636104009)]):
    lines += [f"####<Nov 14, 2026 {tm} EST> <Error> <HTTP> <ps1> <PIA> <[ACTIVE] ExecuteThread: '{th}'> <> <> <{ep}> <BEA-101020> "
              f"<[ServletContext@{n}2] Servlet failed with an IOException",
              "java.io.IOException: Broken pipe", "\tat sun.nio.ch.FileDispatcherImpl.write0(Native Method)", f"\tat x.y(Z.java:{40 + n})>"]
lines += ["####<Nov 14, 2026 10:02:00,1 PM EST> <Debug> <x> <ps1> <PIA> <> <> <> <1731636104010> <BEA-0> <noise>"]
entries = list(wit.entries(src, lines))
kept = [e for e in entries if wit.wanted(src, e)]
tmpls = {wit.template(e, src) for e in kept}
check("[interp] multiline joins a record and its stack trace; drop removes noise; placeholders make two records one template",
      len(entries) == 3 and len(kept) == 2 and len(tmpls) == 1 and "java.io.IOException: Broken pipe" in next(iter(tmpls))
      and "<epoch>" in next(iter(tmpls)), (len(entries), len(kept), tmpls))
check("[interp] the source's own level pattern and timestamp format",
      wit.level(kept[0], None, src) == "error" and (wit.when(src, kept[1]) or "").startswith("2026-11-1"),
      (wit.level(kept[0], None, src), wit.when(src, kept[1])))

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
check("[versions] a checkout's commit, even where git won't run (read from .git, packed refs too)", ew.git_head(g) == "ab" * 20)
own = subprocess.run(["git", "-C", os.path.join(HERE, ".."), "rev-parse", "HEAD"], capture_output=True, text=True)
if own.returncode == 0:
    check("[versions] this repo's own commit, through git", ew.git_head(os.path.join(HERE, "..")) == own.stdout.strip())
open(os.path.join(g, "peopletools.properties"), "w").write("psplatformregname=ORACLE\ntoolsrelease=8.60.07\n")
check("[versions] a version from a file by a pattern (no git: PeopleTools, say)",
      ew.service_version({"version": {"file": os.path.join(g, "peopletools.properties"), "pattern": r"^toolsrelease=(\S+)"}}) == "8.60.07")

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
check("[flows] a client's UDP socket on an ephemeral port isn't a listener",
      [l["port"] for l in ew.parse_ss("udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:41826 0.0.0.0:*", "h")["listening"]] == [5353])


# ---- a round trip: two eaves -> a store -> the ridge, their sources from an applied interpreter
def setup(store, role="eave", hosts=("web-1", "web-2")):
    base = tempfile.mkdtemp(prefix="eaveswatch-test-")
    logs = os.path.join(base, "logs")
    os.makedirs(logs)
    os.makedirs(os.path.join(base, "specs"))
    open(os.path.join(base, "VERSION"), "w").write("abc123def456")
    open(os.path.join(base, "app.cfg"), "w").write("threads=4\n")
    cfgs = {}
    for host in hosts:
        open(os.path.join(logs, f"{host}.log"), "w").close()
        cfgs[host] = ew.make_config({"store": store, "env": "test", "host": host, "role": role,
                                     "state_dir": os.path.join(base, host), "ridge": {"data": os.path.join(base, "ridge")}})
        sp = spec_file({"sources": [{"name": "app", "path": os.path.join(logs, f"{host}.log"), "from_start": True,
                                     "service": "api", "raw": True}],
                        "services": {"api": {"version": {"file": os.path.join(base, "VERSION")},
                                             "watch": [os.path.join(base, "app.cfg")]}},
                        "warmup_minutes": 0}, os.path.join(base, "specs"))
        ew.apply_spec(cfgs[host], sp, "test setup")
    return base, logs, cfgs


def inbox_records(data, kind, host=None):
    out = []
    for root in ("inbox", "archive"):
        for d, _, ns in os.walk(os.path.join(data, root)):
            if f"kind={kind}" in d and (host is None or f"host={host}" in d):
                for n in ns:
                    if n.endswith(".jsonl.gz"):
                        out += ew.unpack(open(os.path.join(d, n), "rb").read())
    return out


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
    recs = ew.unpack(store.get([k for k in keys if "kind=packets" in k and "host=web-1" in k][0]))
    ok_rec = {x["template"]: x for x in recs}.get("INFO request ok in <n>", {})
    check(f"[{label}] packets: templates counted, samples redacted, the version of the code, the interpreter version",
          ok_rec.get("count") == 2 and ok_rec.get("version") == "abc123def456" and ok_rec.get("service") == "api"
          and ok_rec.get("interpreter") == 1 and "hunter2" not in json.dumps(recs) and "password=<redacted>" in json.dumps(recs), recs)
    raw = [k for k in keys if "kind=raw" in k and "host=web-1" in k]
    check(f"[{label}] raw archive (the spec asks for it) is redacted too", raw and "hunter2" not in gzip.decompress(store.get(raw[0])).decode())
    inv = ew.unpack(store.get([k for k in keys if "kind=inventory" in k and "host=web-1" in k][0]))[0]
    check(f"[{label}] inventory: the watched config's hash (not its contents), the interpreter, the user",
          list(inv["watched"].values())[0]["sha"] and "threads" not in json.dumps(inv) and inv["interpreter"] == 1 and inv["user"], inv)
    write(f"{logs}/web-1.log", ["INFO request ok in 3ms"] * 30 + ["ERROR db connection refused to 10.0.1.20:5432"])
    keys2 = eaves["web-1"].tick()
    recs2 = {x["template"]: x for x in ew.unpack(store.get([k for k in keys2 if "kind=packets" in k][0]))}
    check(f"[{label}] a spike and a new template are flagged at the eave",
          recs2["INFO request ok in <n>"]["spike"] and recs2["ERROR db connection refused to <ip>"]["new"], recs2)
    check(f"[{label}] unchanged inventory and flows aren't sent again", not [k for k in keys2 if "kind=inventory" in k], keys2)
    ridge = ew.Ridge(cfgs["web-1"], store_obj)
    got = ridge.sync()
    check(f"[{label}] ridge sync pulls everything but raw", got == len([k for k in keys + keys2 if "kind=raw" not in k]), got)
    check(f"[{label}] a second sync finds nothing new", ridge.sync() == 0)
    digest = ridge.watch()
    check(f"[{label}] the digest: new hosts, the spike, the new template (with its fp and version), saved",
          "## New hosts" in digest and "web-2" in digest and "## Spiking log templates" in digest
          and "ERROR db connection refused to <ip>" in digest and "abc123def456" in digest
          and os.listdir(os.path.join(base, "ridge", "digests")), digest[:1500])
    check(f"[{label}] watch is silent with nothing new", ridge.watch() == "")
    # a deploy, a config change, a new interpreter version: each in the digest
    open(os.path.join(base, "VERSION"), "w").write("fff999")
    write(os.path.join(base, "app.cfg"), ["threads=8"])
    sp2 = spec_file({**json.load(open(os.path.join(cfgs["web-2"]["interpreter"], "v1.json"))), "about": "v2"}, os.path.join(base, "specs"))
    ew.apply_spec(cfgs["web-2"], sp2, "about")
    eaves["web-2"].tick()
    ridge.sync()
    d2 = ridge.watch()
    check(f"[{label}] a deploy, a config change (its hash) and a new interpreter version show in the digest",
          "web-2 api: abc123def456 -> fff999" in d2 and "## Config changes" in d2 and "app.cfg: changed" in d2
          and "## Interpreter versions" in d2 and "web-2: v1 -> v2" in d2, d2)
    # an ask: ridge -> outbox -> store -> eave answers -> ridge
    fp = recs2["ERROR db connection refused to <ip>"]["fp"]
    ridge.ask("web-1", "lines", fp=fp)
    ridge.sync()
    eaves["web-1"].tick()
    ridge.sync()
    d3 = ridge.watch()
    ans = [a for a in inbox_records(ridge.data, "answers") if a.get("lines") is not None]
    check(f"[{label}] an ask is answered from the eave's own logs, redacted, and shows in the digest",
          "## Answers to your asks" in d3 and ans and ans[0]["lines"] == ["ERROR db connection refused to 10.0.1.20:5432"], (d3, ans))
    return base, cfgs


base, cfgs = round_trip("folder", tempfile.mkdtemp(prefix="eaveswatch-store-"))

# a log that rolls by date: tomorrow's file is read from its start, today's (there at the start) from its end
dbase = tempfile.mkdtemp(prefix="eaveswatch-roll-")
dcfg = ew.make_config({"store": os.path.join(dbase, "store"), "env": "test", "host": "ps1", "state_dir": os.path.join(dbase, "s")})
write(os.path.join(dbase, "APPSRV_1114.LOG"), ["PSAPPSRV.1 (3) old line"] * 5)
ew.apply_spec(dcfg, spec_file({"sources": [{"name": "appsrv", "path": os.path.join(dbase, "APPSRV_*.LOG")}], "warmup_minutes": 0},
                              tempfile.mkdtemp()), None)
de = ew.Eave(dcfg)
de.tick()
write(os.path.join(dbase, "APPSRV_1114.LOG"), ["PSAPPSRV.1 (3) later today"])
write(os.path.join(dbase, "APPSRV_1115.LOG"), ["PSAPPSRV.1 (3) tomorrow"] * 4)
de.tick()
got = {}
for k in ew.FolderStore(dcfg["store"]).list("env=test/kind=packets/"):
    for x in ew.unpack(ew.FolderStore(dcfg["store"]).get(k)):
        got[x["template"]] = got.get(x["template"], 0) + x["count"]
check("[eave] a dated log file that appears later is read from its start; what was there at the start, from its end",
      got == {"PSAPPSRV.<n> (<n>) later today": 1, "PSAPPSRV.<n> (<n>) tomorrow": 4}, got)

# ---- interpret: init, test, apply, show, rollback; a pattern that backtracks forever can't hang it
icfg = ew.make_config({"store": os.path.join(dbase, "store2"), "env": "test", "host": "ps2", "state_dir": os.path.join(dbase, "s2")})
cfgp = os.path.join(dbase, "cfg.json")
json.dump({"store": icfg["store"], "env": "test", "host": "ps2", "state_dir": icfg["state_dir"]}, open(cfgp, "w"))
draft = os.path.join(dbase, "draft.json")
o_init = cli("--config", cfgp, "interpret", "init", draft)
spec = json.load(open(draft))
spec["sources"] = [{"name": "appsrv", "path": os.path.join(dbase, "APPSRV_*.LOG")}]
json.dump(spec, open(draft, "w"))
o_test = cli("--config", cfgp, "interpret", "test", draft)
o_apply = cli("--config", cfgp, "interpret", "apply", draft, "--note", "first")
spec["sources"].append({"name": "other", "path": os.path.join(dbase, "APPSRV_1115.LOG")})
json.dump(spec, open(draft, "w"))
o_apply2 = cli("--config", cfgp, "interpret", "apply", draft)
o_show = cli("--config", cfgp, "interpret", "show")
o_back = cli("--config", cfgp, "interpret", "rollback")
check("[interpret] init writes the starter; test replays real lines; apply numbers versions and says what changed",
      o_init.returncode == 0 and o_test.returncode == 0 and "appsrv (files, 2 files): 10 lines" in o_test.stdout
      and "applied v1" in o_apply.stdout and "applied v2 (was v1):\n  + source other" in o_apply2.stdout, o_test.stdout + o_apply2.stdout)
check("[interpret] show lists the active sources and the history; rollback makes the old spec a new version (so it spreads)",
      "interpreter: v2" in o_show.stdout and "other:" in o_show.stdout and "apply v1: first" in o_show.stdout
      and "active: v3, v1's spec again (was v2)" in o_back.stdout and ew.active_spec(icfg)[1] == 3
      and len(ew.active_spec(icfg)[0]["sources"]) == 1, o_show.stdout + o_back.stdout)
bad = dict(spec, sources=[{"name": "x", "path": "~/.ssh/id_rsa"}])
o_bad = cli("--config", cfgp, "interpret", "apply", spec_file(bad, tempfile.mkdtemp()))
check("[interpret] a spec pointing at credentials isn't applied", o_bad.returncode != 0 and "never collected" in o_bad.stderr
      and ew.active_spec(icfg)[1] == 3, o_bad.stderr)
write(os.path.join(dbase, "evil.log"), ["a" * 30 + "b"] * 3)
evil = dict(spec, sources=[{"name": "evil", "path": os.path.join(dbase, "evil.log"), "placeholders": [{"name": "x", "pattern": "(a+)+$"}]}])
t0 = time.time()
etext, eprob, _ = ew.test_spec(icfg, spec_file(evil, tempfile.mkdtemp()), timeout=4)
check("[interpret] a catastrophically backtracking pattern is caught by the time limit, not run on the eave",
      eprob and "backtracking" in etext and time.time() - t0 < 20, etext)


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

    def do_DELETE(self):
        self.verify()
        FakeS3.objects.pop(urllib.parse.unquote(urllib.parse.urlsplit(self.path).path), None)
        self.send_response(204); self.end_headers()

    def do_PUT(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        self.verify(body)
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        cur = FakeS3.objects.get(path)
        inm, im = self.headers.get("If-None-Match"), self.headers.get("If-Match")
        if (inm == "*" and cur is not None) or (im and (cur is None or im.strip('"') != hashlib.md5(cur).hexdigest())):
            self.send_response(412); self.send_header("content-length", "0"); self.end_headers()
            return
        if FakeS3.deny_put:
            err = b"<?xml version='1.0'?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
            self.send_response(403); self.send_header("content-length", str(len(err))); self.end_headers(); self.wfile.write(err)
            return
        FakeS3.objects[path] = body
        self.send_response(200); self.send_header("ETag", f'"{hashlib.md5(body).hexdigest()}"'); self.end_headers()

    def do_GET(self):
        self.verify()
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/" and not q:                    # ListAllMyBuckets: what broad credentials can see
            body = (b'<?xml version="1.0"?><ListAllMyBucketsResult><Buckets><Bucket><Name>bucket</Name></Bucket>'
                    b'<Bucket><Name>payroll-exports</Name></Bucket></Buckets></ListAllMyBucketsResult>')
        elif q.get("list-type") == "2":
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
        self.send_response(200); self.send_header("content-length", str(len(body)))
        self.send_header("ETag", f'"{hashlib.md5(body).hexdigest()}"'); self.end_headers(); self.wfile.write(body)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeS3)
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ.update(AWS_ACCESS_KEY_ID="AKIDTEST", AWS_SECRET_ACCESS_KEY="secret", AWS_REGION="us-east-1")
os.environ.pop("AWS_SESSION_TOKEN", None)
s3 = ew.S3Store("s3://bucket/eaves/v1", endpoint=f"http://127.0.0.1:{srv.server_port}")
round_trip("s3", "s3://bucket/eaves/v1", s3)
check("[s3] every request's signature matches the URL it went to (prefixes with / and = included)", not FakeS3.bad, FakeS3.bad[:3])
check("[s3] objects land under the bucket's prefix", all(k.startswith("/bucket/eaves/v1/env=test/kind=") for k in FakeS3.objects),
      list(FakeS3.objects)[:3])
s3cfg = ew.make_config({"store": "s3://bucket/eaves/v1", "env": "test", "host": "web-7", "role": "eave",
                        "state_dir": tempfile.mkdtemp(prefix="eaveswatch-check-")})
text, problems = ew.run_check(s3cfg, "test.json", s3)
check("[check] an eave on S3: credentials (key masked), a probe under its own host, its asks, the clock; no interpreter yet",
      problems == 0 and "credentials: environment (AWS_ACCESS_KEY_ID) (key AKID…TEST)" in text
      and "store: write: env=test/kind=check/" in text and "host=web-7/" in text and "list asks" in text
      and re.search(r"ok    clock: \d+s", text) and "warn  interpreter: nothing applied yet" in text and "secret" not in text, text)
FakeS3.deny_put = True
text, problems = ew.run_check(s3cfg, "test.json", ew.S3Store("s3://bucket/eaves/v1", endpoint=f"http://127.0.0.1:{srv.server_port}"))
FakeS3.deny_put = False
check("[check] S3 refusing says S3's own reason and the permission to add (its files, and its system's shared state)",
      problems == 2 and "FAIL  store: write: 403 AccessDenied: Access Denied" in text
      and "s3:DeleteObject on s3://bucket/eaves/v1/systems/system=web-7/*" in text
      and "fix: allow s3:PutObject on s3://bucket/eaves/v1/*/host=web-7/*" in text, text)
rd_text, rd_problems = ew.run_check({**s3cfg, "role": "ridge"}, "test.json", s3)
check("[check] a ridge on S3: lists and reads each kind it syncs", rd_problems == 0
      and all(f"test/{k}" in rd_text for k in ("packets", "inventory", "flows", "answers")), rd_text)


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
      ev.last_flush == (0, len(k1) + len(k2)) and "store unreachable" in ev.state["spool_error"]
      and json.load(open(os.path.join(scfgs["web-1"]["state_dir"], "eave.json")))["files"], (ev.last_flush, k1, k2))
flaky.down = False
ev.tick()
check("[spool] back up: everything is sent, oldest first, and the spool empties",
      ev.spooled() == [] and "spool_error" not in ev.state and ev.last_flush[1] == 0, ev.spooled())
rd = ew.Ridge(scfgs["web-1"], flaky)
rd.sync()
counted = sum(x["count"] for x in inbox_records(rd.data, "packets") if x["template"] == "INFO job done in <n>")
check("[spool] no line lost across the outage", counted == 12, counted)
inv = inbox_records(rd.data, "inventory")
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
gap = [x for k in flaky.list("env=test/kind=packets/") if "host=web-2" in k for x in ew.unpack(flaky.get(k)) if x["source"] == "eaveswatch"]
check("[spool] what was dropped is reported once, as an error the ridge will see, once the store's back",
      len(gap) == 1 and gap[0]["level"] == "error" and gap[0]["count"] == ev2.state["spool_dropped"]
      and "store unreachable" in gap[0]["samples"][0] and "spool_dropped_new" not in ev2.state, gap)
rd.sync(deep=True)
late = ew.object_key("test", "packets", "web-9", ew.now_utc() - ew.dt.timedelta(hours=5))
flaky.put(late, ew.pack([{"fp": "late1", "template": "late", "count": 1, "host": "web-9", "window": ["", ""]}]))
check("[ridge] a late file for an old hour waits for the look back, then arrives once",
      rd.sync(deep=False) == 0 and rd.sync(deep=True) == 1 and rd.sync(deep=True) == 0)
rd.watch()
check("[ridge] fetched files are remembered by the data folder itself (archived ones too)", rd.have(late) and rd.sync(deep=True) == 0)

# ---- check: a good eave, then the usual mistakes (in an active spec written by hand)
cbase, clogs, ccfgs = setup(tempfile.mkdtemp(prefix="eaveswatch-check-store-"))
good_cfg = ccfgs["web-1"]
write(f"{clogs}/web-1.log", ["INFO request ok in 12ms token=abc123secret", "INFO request ok in 15ms"])
text, problems = ew.run_check(good_cfg, "good.json")
check("[check] a good eave: the interpreter, its sources and services, a preview, redaction counted, nothing sent but the probe",
      problems == 0 and "all good" in text and "ok    interpreter: v1: 1 sources, 1 services" in text
      and "1x  [app] INFO request ok in <n> token=<redacted>" in text and "1 values redacted" in text
      and "watched files: 1 hashed" in text and "abc123secret" not in text
      and not [k for k in ew.FolderStore(good_cfg["store"]).list("") if "kind=check" not in k and not k.endswith("/.check")], text)
d = good_cfg["interpreter"]
v1 = json.load(open(os.path.join(d, "v1.json")))
json.dump({**v1, "sources": v1["sources"] + [{"name": "nginx", "path": "/nonexistent/*.log"}],
           "services": {**v1["services"], "worker": {"git": "/nonexistent"}}}, open(os.path.join(d, "v9.json"), "w"))
json.dump({"version": 9}, open(os.path.join(d, "active.json"), "w"))
text, problems = ew.run_check(good_cfg, "bad.json")
check("[check] the usual mistakes, each with its fix: a glob matching nothing, a service with no version",
      problems == 2 and "FAIL  source nginx: /nonexistent/*.log matches no files" in text
      and "FAIL  service worker: no version found" in text and text.count("fix: ") == 2, text)
json.dump({**v1, "sources": [{"name": "odd"}]}, open(os.path.join(d, "v9.json"), "w"))
text, problems = ew.run_check(good_cfg, "bad.json")
check("[check] an active spec that doesn't validate is a failure, and the eave runs on the starter meanwhile",
      problems >= 1 and "FAIL  interpreter: v9 doesn't validate" in text and ew.load_interpreter(good_cfg).version is None, text)

# ---- discovery: a real process here, its open log and its listening port
dd = tempfile.mkdtemp(prefix="eaveswatch-disc-")
plog = os.path.join(dd, "svc", "logs", "server.log")
os.makedirs(os.path.dirname(plog))
child = subprocess.Popen([sys.executable, "-c",
                          "import socket,sys,time; f=open(sys.argv[1],'a'); f.write('svc started ok\\n'); f.flush(); "
                          "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); print(s.getsockname()[1], flush=True); time.sleep(120)",
                          plog], stdout=subprocess.PIPE, text=True, cwd=os.path.join(dd, "svc"))
port = int(child.stdout.readline())
fcfg = ew.make_config({"store": os.path.join(dd, "store"), "env": "test", "host": "box", "role": "finial",
                       "state_dir": os.path.join(dd, "state")})
rep, ch = ew.run_discovery(fcfg)
mine = [g for g in rep["processes"] if plog in g["writes"]]
logd = [f for f in rep["logs"] if f["path"] == plog]
check("[discover] a process here: the log it has open for writing, the port it listens on, where it runs",
      mine and f"{port}/tcp" in mine[0]["listen"] and mine[0]["cwd"] == os.path.join(dd, "svc"), mine[:1] or rep["processes"][:3])
check("[discover] its log is listed with a redacted sample, who writes it, and that it isn't collected",
      logd and logd[0]["tail"] == ["svc started ok"] and logd[0]["written_by"] and not logd[0]["collected_by"]
      and plog in rep["uncollected"], logd)
check("[discover] the report is saved (JSON and the readable summary), and the first look has nothing to compare with",
      os.path.exists(os.path.join(fcfg["ridge"]["data"], "discovery", "latest.md")) and ch == {}
      and "## Processes" in open(os.path.join(fcfg["ridge"]["data"], "discovery", "latest.md")).read())
ew.apply_spec(fcfg, spec_file({"sources": [{"name": "svc", "path": os.path.join(dd, "svc", "logs", "*.log")}], "warmup_minutes": 0}, dd), "svc")
rep2, _ = ew.run_discovery(fcfg)
check("[discover] once a spec collects it, the log says by which source",
      [f["collected_by"] for f in rep2["logs"] if f["path"] == plog] == ["svc"] and plog not in rep2["uncollected"])

# ---- a finial: eave, ridge and reviewer on one box; files to the store (the archive) and straight to the ridge
fr = ew.Ridge(fcfg)
fe = ew.Eave(fcfg, inbox=fr.p("inbox"))
fe.state["started"] = "2020-01-01T00:00:00Z"
fe.tick()
write(plog, ["ERROR svc lost its db connection to 10.0.0.9:1521"] * 3)
fe.tick()
fd = fr.watch()
check("[finial] the digest comes straight from the eave, no sync from the store",
      "ERROR svc lost its db connection to <ip>" in fd and "## New hosts" in fd, fd[:800])
check("[finial] the store still gets every file (the archive); the ridge never gets raw",
      ew.FolderStore(fcfg["store"]).list("env=test/kind=packets/") and not inbox_records(fr.data, "raw"))
fp = [x["fp"] for x in inbox_records(fr.data, "packets") if "lost its db" in x["template"]][0]
fr.ask("box", "lines", fp=fp)
fe.tick()
fd2 = fr.watch()
fans = [a for a in inbox_records(fr.data, "answers") if a.get("lines")]
check("[finial] an ask is answered from the ridge's own outbox", "## Answers to your asks" in fd2 and fans
      and fans[0]["lines"][0] == "ERROR svc lost its db connection to 10.0.0.9:1521", (fd2, fans))
child.kill()
child.wait()
time.sleep(0.2)
_, ch3 = ew.run_discovery(fcfg)
fd3 = fr.watch()
check("[finial] what changed on the box (here: a listener gone) comes in the digest",
      f"{port}/tcp" in ch3.get("listening_gone", []) and "## What changed on this box" in fd3 and "listeners gone" in fd3, (ch3, fd3))
ftext, fprob = ew.run_check(fcfg, "finial.json")
check("[check] a finial only writes to the store (its asks and ridge are local): one permission to check",
      fprob == 0 and "store: write" in ftext and "list asks" not in ftext and "interpreter: v1" in ftext, ftext)
o_fin = cli("--config", os.path.join(dd, "fcfg.json"), "finial", "--once") if json.dump(
    {"store": fcfg["store"], "env": "test", "host": "box", "role": "finial", "state_dir": fcfg["state_dir"]},
    open(os.path.join(dd, "fcfg.json"), "w")) is None else None
check("[finial] eaveswatch finial --once: a node's tick (the ridge duty, a job for what discovery saw), the spool sent",
      o_fin.returncode == 0 and "this node took the ridge duty" in o_fin.stdout and "sent " in o_fin.stdout, o_fin.stdout + o_fin.stderr)

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
check("[findings] recorded once, then counted as seen again", first.endswith("recorded") and "seen again (now 2 times)" in again)
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
out = cli("--config", cfg_path, "key", "flows")
check("[cli] key prints where a file would go", re.match(r"env=test/kind=flows/dt=\d{4}-\d\d-\d\d/hour=\d\d/host=cli-1/cli-1_", out.stdout),
      out.stdout + out.stderr)
out = cli("--config", cfg_path, "ridge", "watch")
check("[cli] ridge watch with nothing new prints nothing (a quiet wake)", out.returncode == 0 and out.stdout == "", out.stdout + out.stderr)
chk = cli("--config", cfg_path, "check")
json.dump({"store": os.path.join(base, "store"), "state_dir": os.path.join(base, "cli2"), "host": "cli-1",
           "sources": [{"name": "x", "path": "/nonexistent/*"}]}, open(cfg_path + ".old", "w"))
old = cli("--config", cfg_path + ".old", "check")
check("[cli] check exits 0 when all's well; log settings in the config are ignored, and it says where they go now",
      chk.returncode == 0 and "all good" in chk.stdout and old.returncode == 0
      and "belong in the interpreter spec now" in old.stderr, chk.stdout[-300:] + old.stderr)
json.dump({"store": "/tmp/x", "role": "local"}, open(cfg_path + ".role", "w"))
o_role = cli("--config", cfg_path + ".role", "check")
check("[cli] an unknown role is refused (finial is the one-box role)", o_role.returncode != 0 and "finial" in o_role.stderr, o_role.stderr)
chores = tempfile.mkdtemp(prefix="eaveswatch-chores-")
out = cli("chore", chores)
cj = json.load(open(os.path.join(chores, "eaveswatch", "chore.json"))) if out.returncode == 0 else {}
md = open(os.path.join(chores, "eaveswatch", "CHORE.md")).read() if out.returncode == 0 else ""
check("[chore] eaveswatch chore writes the reviewer chore: its full command path, a quiet watch, safe mode writing only data, "
      "setup with the human",
      cj.get("name") == "eaveswatch" and cj["config"]["wake"]["command"] == "{{command}} --config {{config}} watch"
      and os.path.isabs(cj["settings"]["command"]["default"].split()[0]) and "eaveswatch" in cj["settings"]["command"]["default"]
      and "{{command}} --config {{config}} discover" in md
      and cj["config"]["safe_mode"] == {"write": ["{{data}}"]} and "## Setting up" in md and "Ask your human, once" in md
      and "## The bar for a finding" in md and "Adding is your human's" in md, out.stdout + out.stderr)
again = cli("chore", chores)
check("[chore] an installed chore isn't replaced without --force", again.returncode != 0 and "--force" in again.stderr, again.stderr)

# ---- setup: one command (here: a folder store, no services, a stand-in hobkin that records what it's given)
sh = tempfile.mkdtemp(prefix="eaveswatch-setup-")
rec = os.path.join(sh, "hobkin-args.json")
open(os.path.join(sh, "fake_hobkin.py"), "w").write("import json,sys; json.dump(sys.argv[1:], open(sys.argv[0] + '.out', 'w'))")
senv = {**os.environ, "HOME": sh, "HOBKIN_HOME": os.path.join(sh, ".hobkins"),
        "EAVESWATCH_HOBKIN": f"{sys.executable} {os.path.join(sh, 'fake_hobkin.py')}"}
srun = lambda *a: subprocess.run([sys.executable, EW] + list(a), capture_output=True, text=True, env=senv, stdin=subprocess.DEVNULL)
o1 = srun("https://api.example.test/v1", "some-model", "sk-test", "--store", os.path.join(sh, "store"), "--no-service")
got = json.load(open(os.path.join(sh, "fake_hobkin.py.out"))) if os.path.exists(os.path.join(sh, "fake_hobkin.py.out")) else []
scfg = json.load(open(os.path.join(sh, ".config", "eaveswatch", "finial.json"))) if o1.returncode == 0 else {}
check("[setup] eaveswatch URL MODEL KEY: a finial config, check run, the chore installed, then hobkin's own setup with the chore",
      o1.returncode == 0 and scfg.get("role") == "finial" and scfg.get("state_dir") == "~/eaveswatch"
      and "check: all good" in o1.stdout and os.path.isdir(os.path.join(sh, "eaveswatch", "ridge"))
      and os.path.exists(os.path.join(sh, ".hobkins", "_shared", "chores", "eaveswatch", "chore.json"))
      and got[:3] == ["https://api.example.test/v1", "some-model", "sk-test"]
      and got[3:5] == ["--chore", "eaveswatch"] and f"data={os.path.join(sh, 'eaveswatch', 'ridge')}" in got
      and "--safe" in got and "--chat" in got and "--no-service" in got and any(x.startswith("command=") for x in got),
      o1.stdout + o1.stderr + json.dumps(got))
o2 = srun("https://api.example.test/v1", "some-model", "--no-service", "--no-chat")
check("[setup] run again, it uses the setup there is", o2.returncode == 0 and "using " in o2.stdout, o2.stdout + o2.stderr)
o3 = srun("https://api.example.test/v1", "some-model", "--store", os.path.join(sh, "other"), "--no-service")
check("[setup] a different store isn't put over an existing setup without --force",
      o3.returncode != 0 and "--force replaces it" in o3.stderr, o3.stderr)
fresh = tempfile.mkdtemp(prefix="eaveswatch-setup2-")
o4 = subprocess.run([sys.executable, EW, "https://api.example.test/v1", "some-model", "--no-service"], capture_output=True,
                    text=True, stdin=subprocess.DEVNULL, env={**senv, "HOME": fresh, "AWS_REGION": "us-east-1"})
check("[setup] with no bucket and nobody to ask (no terminal), it says to give --bucket, and writes nothing",
      o4.returncode != 0 and "--bucket" in o4.stderr and not os.path.exists(os.path.join(fresh, ".config", "eaveswatch")), o4.stderr)

# ---- alerts: rules checked by the eave, delivered by the loop; the findings page; IAM
ab = tempfile.mkdtemp(prefix="eaveswatch-alerts-")
alog = os.path.join(ab, "app.log")
open(alog, "w").close()
mailbox = os.path.join(ab, "mailbox.txt")
fake_sendmail = os.path.join(ab, "sendmail")
open(fake_sendmail, "w").write(f"#!/bin/sh\ncat >> {mailbox}\necho '----' >> {mailbox}\n")
os.chmod(fake_sendmail, 0o755)
pub = os.path.join(ab, "www")
os.makedirs(pub)
acfg = ew.make_config({"store": os.path.join(ab, "store"), "env": "test", "host": "ps1", "role": "finial",
                       "state_dir": os.path.join(ab, "state"), "publish": {"dir": pub},
                       "notify": {"email": "me@example.test", "sendmail": fake_sendmail, "per_hour": 3}})
aerr = ew.validate_spec({"sources": [{"name": "app", "path": alog}], "alerts": [
    {"name": "x"}, {"name": "y", "match": {"template": "(", "count": 0}}, {"name": "z", "silent": {"source": "nope", "minutes": 5}},
    {"name": "w", "unit_failed": ["a"], "match": {"level": "error"}, "severity": "loud"}]})
check("[alerts] rules are validated: one kind each, regexes, sources that exist, counts, severities",
      all(any(b in e for e in aerr) for b in ["(x): give exactly one", "bad regex", "match.count", "(z).silent", "(w): give exactly one",
                                                "severity is page or warn"]), aerr)
ew.apply_spec(acfg, spec_file({"sources": [{"name": "app", "path": alog, "from_start": True}], "warmup_minutes": 0, "alerts": [
    {"name": "db-down", "severity": "page", "about": "the app can't reach its database",
     "match": {"template": "connection refused", "count": 3, "minutes": 5}},
    {"name": "app-quiet", "silent": {"source": "app", "minutes": 1}},
    {"name": "unit-failed", "severity": "page", "unit_failed": ["psappsrv.service"]}]}, ab), "alerts")
ar = ew.Ridge(acfg)
ae = ew.Eave(acfg, inbox=ar.p("inbox"))
ae.failed_units = lambda: set()
write(alog, ["ERROR connection refused to db:1521"] * 2)
ae.tick()
q = lambda: sorted(os.listdir(ew.notify_dir(acfg, "queue"))) if os.path.isdir(ew.notify_dir(acfg, "queue")) else []
check("[alerts] under the count in the window: nothing fires", q() == [])
write(alog, ["ERROR connection refused to db:1521"] * 2)
ae.tick()
note = ew.read_json(ew.notify_dir(acfg, "queue", q()[0]), {}) if q() else {}
check("[alerts] over it: fires once, queued for the person straight away (a finial), with the samples and why",
      len(q()) == 1 and note.get("severity") == "page" and "db-down" in note.get("subject", "")
      and "4 matching entries in 5 min" in note.get("body", "") and "the app can't reach its database" in note["body"]
      and "ERROR connection refused to db:1521" in note["body"], note)
write(alog, ["ERROR connection refused to db:1521"] * 5)
ae.tick()
check("[alerts] within the cooldown it doesn't fire again", len(q()) == 1, q())
ae.failed_units = lambda: {"psappsrv.service", "other.service"}
ae.state["alert_state"]["heard"]["app"] = time.time() - 120
ae.tick()
subjects = [ew.read_json(ew.notify_dir(acfg, "queue", n), {}).get("subject", "") for n in q()]
check("[alerts] a failed unit it names, and a source gone quiet, fire too",
      any("unit-failed: psappsrv.service has failed" in x for x in subjects) and not any("other.service" in x for x in subjects)
      and any("app-quiet: app has written nothing for 2 min" in x for x in subjects), subjects)
sent, left = ew.deliver_notes(acfg)
mail = open(mailbox).read() if os.path.exists(mailbox) else ""
check("[alerts] delivered by sendmail, at most per_hour an hour (the rest wait, and the last says so)",
      sent == 3 and left == 0 and mail.count("----") == 3 and "Subject: [ALERT] ps1: db-down" in mail and "To: me@example.test" in mail,
      (sent, left, mail[:600]))
ew.queue_note(acfg, "one more", "x")
check("[alerts] over the hourly cap, a note waits in the queue", ew.deliver_notes(acfg) == (0, 1) and len(q()) == 1)
d_alerts = ar.watch()
check("[alerts] the digest starts with what fired (already sent: follow up), and keeps them for the page",
      d_alerts.split("\n\n")[1].startswith("## Alerts fired") and "**db-down** [page]" in d_alerts
      and os.path.exists(ar.p("alerts.jsonl")), d_alerts[:600])
ew.finding_add(acfg, {"category": "security/injection", "location": "app <log>", "claim": "a log line said <script>alert(1)</script>",
                      "evidence": "e", "scenario": "s", "action": "a", "confidence": "low"})
where = ew.publish_report(acfg)
page = open(os.path.join(pub, "index.html")).read()
check("[report] the findings page: open findings, recent alerts, what's collected; copied to the web folder",
      where == pub and "Open findings" in page and "db-down" in page and "unit-failed" in page
      and os.path.exists(ar.p("report", "index.html")), where)
check("[report] text from logs is escaped (it can't run in the page)",
      "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page)
check("[report] unchanged, it isn't written again", ew.publish_report(acfg) is None)
unsent_cfg = ew.make_config({"store": os.path.join(ab, "s2"), "env": "test", "host": "ps2", "role": "finial", "state_dir": os.path.join(ab, "st2")})
ew.queue_note(unsent_cfg, "hello", "x")
check("[alerts] with no channel, notes are kept (notify/unsent), not lost", ew.deliver_notes(unsent_cfg) == (0, 0)
      and os.listdir(ew.notify_dir(unsent_cfg, "unsent")))

# SMTP, by a relay (a tiny one here)
import socketserver
got_mail = []


class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 fake\r\n")
        data = False
        buf = []
        for raw in self.rfile:
            line = raw.decode(errors="replace").rstrip("\r\n")
            if data:
                if line == ".":
                    got_mail.append("\n".join(buf)); data = False; self.wfile.write(b"250 ok\r\n")
                else:
                    buf.append(line)
                continue
            cmd = line[:4].upper()
            if cmd == "DATA":
                data = True; self.wfile.write(b"354 go\r\n")
            elif cmd == "QUIT":
                self.wfile.write(b"221 bye\r\n"); return
            else:
                self.wfile.write(b"250 ok\r\n")


smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SMTP)
threading.Thread(target=smtp.serve_forever, daemon=True).start()
scfg2 = ew.make_config({"store": os.path.join(ab, "s3"), "env": "test", "host": "ps3", "role": "finial", "state_dir": os.path.join(ab, "st3"),
                        "notify": {"email": "me@example.test", "smtp": f"127.0.0.1:{smtp.server_address[1]}"}})
ew.queue_note(scfg2, "by relay", "through SMTP")
check("[alerts] by an SMTP relay instead of sendmail", ew.deliver_notes(scfg2) == (1, 0) and got_mail and "through SMTP" in got_mail[0],
      got_mail)
ctext, cprob = ew.run_check(scfg2, "x.json")
check("[check] the alert channel is checked (the relay answers; nothing is sent)", "ok    alerts: to me@example.test by SMTP" in ctext
      and len(got_mail) == 1, ctext)

# the commands: notify (from hobkin's alert_command too), notify --test, iam
acfg_path = os.path.join(ab, "acfg.json")
json.dump({"store": acfg["store"], "env": "test", "host": "ps1", "role": "finial", "state_dir": acfg["state_dir"],
           "notify": {"email": "me@example.test", "sendmail": fake_sendmail, "per_hour": 50}}, open(acfg_path, "w"))
on = subprocess.run([sys.executable, EW, "--config", acfg_path, "notify"], capture_output=True, text=True,
                    env={**os.environ, "HOBKIN_ALERT": "hobkin eaveswatch paused: the model refused"}, stdin=subprocess.DEVNULL)
check("[notify] hobkin's alert_command ($HOBKIN_ALERT) is queued for the person",
      on.returncode == 0 and "queued:" in on.stdout and any("model refused" in json.dumps(ew.read_json(ew.notify_dir(acfg, "queue", n), {}))
                                                           for n in q()), on.stdout + on.stderr)
ot = cli("--config", acfg_path, "notify", "--test")
check("[notify] --test sends one now", ot.returncode == 0 and "sent" in ot.stdout and "test note" in open(mailbox).read(), ot.stdout + ot.stderr)
iam_path = os.path.join(ab, "iam.json")
json.dump({"store": "s3://my-bucket/eaveswatch", "env": "prod", "host": "ps1", "system": "ps-hr", "role": "finial",
           "state_dir": os.path.join(ab, "iam")}, open(iam_path, "w"))
oi = cli("--config", iam_path, "iam")
pol = json.loads(oi.stdout) if oi.returncode == 0 else {}
sids = {st["Sid"]: st for st in pol.get("Statement", [])}
check("[iam] a node: write its own host's data, the system's shared state, and read its environment's data (any node may hold the ridge)",
      set(sids) == {"WriteOwnHost", "SystemState", "List", "ReadAsksAndAnswers", "RidgeDutyReads"}
      and "arn:aws:s3:::my-bucket/eaveswatch/*/host=ps1/*" in sids["WriteOwnHost"]["Resource"]
      and sids["SystemState"]["Resource"] == "arn:aws:s3:::my-bucket/eaveswatch/systems/system=ps-hr/*"
      and "s3:DeleteObject" in sids["SystemState"]["Action"], oi.stdout)
check("[iam] a folder store needs no policy, and says so", "no IAM policy needed" in cli("--config", acfg_path, "iam").stderr)
s3f = ew.make_config({"store": "s3://bucket/eaves/v1", "env": "test", "host": "ps9", "role": "finial", "state_dir": tempfile.mkdtemp()})
btext, _ = ew.run_check(s3f, "x", ew.S3Store("s3://bucket/eaves/v1", endpoint=f"http://127.0.0.1:{srv.server_port}"))
check("[check] credentials that can list every bucket are noticed, and `iam` named", "warn  credentials: they can list every bucket (2)" in btext
      and "eaveswatch iam" in btext, btext)
# a fleet: the ridge's sync sends alerts from the store on to the person
fl_store = os.path.join(ab, "fleet-store")
fe_cfg = ew.make_config({"store": fl_store, "env": "test", "host": "web-1", "state_dir": os.path.join(ab, "fe")})
fr_cfg = ew.make_config({"store": fl_store, "env": "test", "host": "hub", "role": "ridge", "state_dir": os.path.join(ab, "fr")})
ew.FolderStore(fl_store).put(ew.object_key("test", "alerts", "web-1", ew.now_utc()),
                             ew.pack([{"rule": "r1", "severity": "page", "host": "web-1", "at": "x", "detail": "it broke"}]))
ew.Ridge(fr_cfg).sync()
fq = os.listdir(ew.notify_dir(fr_cfg, "queue"))
check("[alerts] in a fleet, the ridge queues an eave's alert as it syncs it", len(fq) == 1
      and "r1: it broke" in ew.read_json(ew.notify_dir(fr_cfg, "queue", fq[0]), {})["subject"])

# setup asks where alerts go and about the web folder; flags answer instead
sh2 = tempfile.mkdtemp(prefix="eaveswatch-setup3-")
os.makedirs(os.path.join(sh2, "www"))
o5 = subprocess.run([sys.executable, EW, "https://api.example.test/v1", "m", "--store", os.path.join(sh2, "store"), "--no-service",
                     "--alert-email", "me@example.test", "--smtp", f"127.0.0.1:{smtp.server_address[1]}",   # no sendmail on CI
                     "--publish-dir", os.path.join(sh2, "www")], capture_output=True, text=True,
                    stdin=subprocess.DEVNULL, env={**senv, "HOME": sh2})
c5 = json.load(open(os.path.join(sh2, ".config", "eaveswatch", "finial.json"))) if o5.returncode == 0 else {}
check("[setup] where alerts go and the web folder for the findings page, from flags (asked for at a terminal)",
      c5.get("notify", {}).get("email") == "me@example.test" and c5.get("notify", {}).get("smtp", "").startswith("127.0.0.1:")
      and c5.get("publish", {}).get("dir") == os.path.join(sh2, "www")
      and "anyone who can reach that site sees the findings" in o5.stdout, o5.stdout + o5.stderr)

# ---- a cluster: three nodes of one system on a shared store; any of them can drop out
cb = tempfile.mkdtemp(prefix="eaveswatch-cluster-")
cstore = os.path.join(cb, "store")
clog = os.path.join(cb, "app.log")
open(clog, "w").close()
cmail = os.path.join(cb, "mail.txt")
csend = os.path.join(cb, "sendmail")
open(csend, "w").write(f"#!/bin/sh\ncat >> {cmail}\necho '----' >> {cmail}\n")
os.chmod(csend, 0o755)
FAST = {"lease_seconds": 2, "claim_seconds": 3, "job_wait_seconds": 1, "node_gone_seconds": 3}


def node_cfg(host, store=cstore):
    path = os.path.join(cb, f"{host}.json")
    json.dump({"role": "finial", "env": "test", "host": host, "system": "ps", "store": store, "cluster": FAST,
               "state_dir": os.path.join(cb, host), "publish": {"dir": os.path.join(cb, "www", host)},
               "notify": {"email": "me@example.test", "sendmail": csend, "per_hour": 50}}, open(path, "w"))
    os.makedirs(os.path.join(cb, "www", host), exist_ok=True)
    return ew.load_config(path), path


c1, c1p = node_cfg("n1")
c2, _ = node_cfg("n2")
c3, _ = node_cfg("n3")
ew.apply_spec(c1, spec_file({"sources": [{"name": "app", "path": clog}], "warmup_minutes": 0, "alerts": [
    {"name": "storm", "severity": "page", "match": {"template": "connection refused", "count": 2, "minutes": 5}},
    {"name": "unit", "unit_failed": ["psappsrv.service"]}]}, cb), "first")
n1, n2, n3 = ew.Node(c1), ew.Node(c2), ew.Node(c3)
for n in (n1, n2, n3):
    n.eave.failed_units = lambda: set()
    n.eave.state["started"] = "2020-01-01T00:00:00Z"
said1 = n1.tick()
n2.tick(); n3.tick()
check("[cluster] one node holds the ridge duty; the others don't",
      n1.leading and not n2.leading and not n3.leading and "this node took the ridge duty" in said1, said1)
check("[cluster] the interpreter applied on one node reaches the others",
      ew.active_spec(c2)[1] == 1 and ew.active_spec(c3)[1] == 1 and ew.active_spec(c3)[0].get("alerts"),
      (ew.active_spec(c2)[1], ew.active_spec(c3)[1]))
open(os.path.join(c1["ridge"]["data"], "REVIEW.md"), "w").write("# The PS system\nSign-on failures matter.\n")
n1.tick(); n2.tick()
check("[cluster] the charter edited on one node reaches the others",
      "Sign-on failures" in ew._read(os.path.join(c2["ridge"]["data"], "REVIEW.md")))
# findings: recorded anywhere, on every node's page
cf = {"category": "security/authn", "location": "pia signon", "claim": "sign-on failures from one address <b>",
      "evidence": "e", "scenario": "s", "action": "a", "confidence": "medium"}
cfid = ew.finding_add(c2, cf).split()[0]
n2.tick(); n3.tick(); n1.tick()
page3 = open(os.path.join(cb, "www", "n3", "index.html")).read()
check("[cluster] a finding recorded on one node is on every node's page (behind a load balancer, any node answers)",
      cfid in ew.findings(c1) and cfid in ew.findings(c3) and "sign-on failures from one address &lt;b&gt;" in page3)
ew.finding_add(c3, {**cf, "evidence": "more, from n3"})
ew.finding_status(c1, cfid, "dismissed", "a load-test address")
for n in (n3, n1, n2, n3, n1):
    n.tick()
f1, f3 = ew.findings(c1)[cfid], ew.findings(c3)[cfid]
check("[cluster] the same finding from two nodes is one, seen twice; a dismissal anywhere holds everywhere",
      f1["status"] == f3["status"] == "dismissed" and f1["sightings"] == f3["sightings"] == 2, (f1, f3))
# an alert where the evidence is: the job goes to that node, one email for the system
n2.eave.failed_units = lambda: {"psappsrv.service"}
said2 = n2.tick()
n1.tick(); n3.tick()
cst = ew.FolderStore(cstore)
aj = [j for j in (ew.jget(cst, k)[0] for k in cst.list(ew.sys_key(c2, "jobs") + "/")) if j["title"].startswith("alert unit on n2")]
check("[cluster] an alert on n2: a job naming n2, claimed by n2 (not the others), and its reviewer woken with it",
      aj and (aj[0].get("claim") or {}).get("host") == "n2" and n2.st.get("active") == aj[0]["id"]
      and n1.st.get("active") != aj[0]["id"] and n3.st.get("active") != aj[0]["id"]
      and "# Review job" in ew.node_watch(c2) and ew.node_watch(c2) == "", (said2, aj))
write(clog, ["ERROR connection refused to db:1521"] * 3)
n1.tick(); n3.tick(); n2.tick()
mail = open(cmail).read() if os.path.exists(cmail) else ""
check("[cluster] the same error storm seen by two nodes: one email for the system, not two",
      len(re.findall(r"Subject: \[ALERT\] n\d: storm", mail)) == 1
      and mail.count("unit: psappsrv.service has failed") == 1, mail.count("----"))
# the reviewer says it's done: the system knows
jid = aj[0]["id"]
ew.write_json(os.path.join(c2["ridge"]["data"], "jobs", "done", f"{jid}.json"), {"note": "PSAPPSRV restarted by ops"})
n2.tick()
j_now, _ = ew.jget(ew.FolderStore(cstore), ew.sys_key(c2, "jobs", f"{jid}.json"))
n1.tick()
check("[cluster] a job done on its node is done for the system, with the reviewer's note, on the page",
      j_now["done"]["note"] == "PSAPPSRV restarted by ops" and n2.st.get("active") != jid
      and "done on n2: PSAPPSRV restarted by ops" in open(os.path.join(cb, "www", "n1", "index.html")).read(), j_now)
# a job whose node dies is taken by another once its claim runs out
jx = n3.make_job("test:dies-with-n3", "evidence on n3", "n3", "look at n3", priority=0)
n3.tick()
check("[cluster] n3 claims its own job", (n3.st.get("active") or "") in (jx or ""), n3.st)
jx_id = jx.split()[1].rstrip(":") if jx else ""
end = time.time() + 4.5                                 # n3 is gone: no ticks, no renewals; the others carry on,
while time.time() < end:                                # their reviewers finishing what they had
    for n in (n1, n2):
        if n.st.get("active") and n.st["active"] != jx_id:
            ew.write_json(os.path.join(n.data, "jobs", "done", f"{n.st['active']}.json"), {"note": "done"})
        n.tick()
taken = [n.host for n in (n1, n2) if n.st.get("active") and n.st["active"] in (jx or "")]
check("[cluster] n3 dies mid-review: its claim runs out and another node takes the job", taken, (n1.st, n2.st))
gone_mail = open(cmail).read()
check("[cluster] the node holding the ridge notices n3 went silent: one warning, and a job",
      "node n3 is gone" in gone_mail and gone_mail.count("node n3 is gone") == 1, gone_mail[-600:])
# the ridge holder leaves cleanly: another takes over at once
n1.leave()
said_n2 = n2.tick()
check("[cluster] the ridge holder leaves cleanly (scale-in): the lease is given back and another node takes it",
      n2.leading and any("took the ridge duty" in x for x in said_n2), said_n2)
hb1, _ = ew.jget(ew.FolderStore(cstore), ew.sys_key(c1, "nodes", "n1.json"))
time.sleep(3.2)
n2.tick()
check("[cluster] a node that said it was leaving isn't reported as gone", hb1.get("left")
      and "node n1 is gone" not in open(cmail).read())
# two nodes apply an interpreter at the same moment: one wins, the other is told
n3 = ew.Node(c3)
ew.apply_spec(c2, spec_file({"sources": [{"name": "app", "path": clog}], "about": "from n2"}, cb), "n2's")
ew.apply_spec(c3, spec_file({"sources": [{"name": "app", "path": clog}], "about": "from n3"}, cb), "n3's")
n2.tick(); n3.tick()
note3 = ew.node_watch(c3)
check("[cluster] two interpreters at once: the first shared stands everywhere; the other node's reviewer is told",
      ew.active_spec(c3)[0].get("about") == "from n2" and "lost a race" in note3
      and os.path.exists(os.path.join(c3["interpreter"], "v2.lost.json")), (ew.active_spec(c3)[0].get("about"), note3[:200]))
# asks between nodes: n2's reviewer asks n3; n3 answers through the store; n2 hears back
ew.Ridge(c2).ask("n3", "inventory")
n2.tick(); n3.tick(); n2.tick()
w2 = ew.node_watch(c2)
check("[cluster] an ask to another node is answered through the store, back to the reviewer who asked",
      "an answer from n3" in w2 and '"inventory"' in w2, w2[:300])
# a new instance joins: no questions, the rest on its first tick
ew.write_json(os.path.join(c1["ridge"]["data"], "reviewer.json"), {"url": "https://api.example.test/v1", "model": "m",
                                                                   "key_env": "EAVESWATCH_MODEL_KEY"})
ew.share_config(c1, c1p)
jb = tempfile.mkdtemp(prefix="eaveswatch-join-")
open(os.path.join(jb, "fake_hobkin.py"), "w").write("import json,sys; json.dump(sys.argv[1:], open(sys.argv[0] + '.out', 'w'))")
jenv = {**os.environ, "HOME": jb, "HOBKIN_HOME": os.path.join(jb, ".hobkins"), "EAVESWATCH_MODEL_KEY": "sk-from-env",
        "EAVESWATCH_HOBKIN": f"{sys.executable} {os.path.join(jb, 'fake_hobkin.py')}"}
jr = subprocess.run([sys.executable, EW, "join", cstore, "ps", "--no-service", "--host", "n4"], capture_output=True, text=True,
                    env=jenv, stdin=subprocess.DEVNULL)
real_home, os.environ["HOME"] = os.environ.get("HOME"), jb
c4 = ew.load_config(os.path.join(jb, ".config", "eaveswatch", "finial.json")) if jr.returncode == 0 else None
os.environ["HOME"] = real_home
hargs = json.load(open(os.path.join(jb, "fake_hobkin.py.out"))) if os.path.exists(os.path.join(jb, "fake_hobkin.py.out")) else []
check("[join] a new instance joins with no questions: its own host, the system's interpreter, charter and findings on its first tick",
      c4 and c4["host"] == "n4" and c4["system"] == "ps" and ew.active_spec(c4)[0].get("about") == "from n2"
      and "Sign-on failures" in ew._read(os.path.join(c4["ridge"]["data"], "REVIEW.md")) and cfid in ew.findings(c4),
      jr.stdout + jr.stderr)
check("[join] its reviewer starts with the key from the environment, and no chat (nobody's there)",
      hargs[:3] == ["https://api.example.test/v1", "m", "sk-from-env"] and "--chat" not in hargs and "--no-service" in hargs, hargs)
jr2 = subprocess.run([sys.executable, EW, "join", cstore, "nope", "--no-service"], capture_output=True, text=True,
                     env={**jenv, "HOME": tempfile.mkdtemp()}, stdin=subprocess.DEVNULL)
check("[join] no such system: it says how one starts", jr2.returncode != 0 and "--system nope" in jr2.stderr, jr2.stderr)
# the same lease and claims against S3's conditional writes (the fake checks If-None-Match and If-Match)
s3a, _ = node_cfg("s3a", "s3://bucket/eaves/v1")
s3b, _ = node_cfg("s3b", "s3://bucket/eaves/v1")
for c in (s3a, s3b):
    c["endpoint"] = f"http://127.0.0.1:{srv.server_port}"
na, nb = ew.Node(s3a), ew.Node(s3b)
na.tick(); nb.tick()
sj = na.make_job("test:s3", "on S3", "s3b", "x", priority=0)
nb.tick(); na.tick()
ctext, _ = ew.run_check(s3a, "x", ew.S3Store("s3://bucket/eaves/v1", endpoint=f"http://127.0.0.1:{srv.server_port}"))
check("[check] the store is checked for conditional writes (the lease and claims rely on them)",
      "ok    store: conditional writes: honoured" in ctext, ctext)
check("[cluster] on S3: one ridge holder, and a job claimed once (conditional writes)",
      na.leading != nb.leading and nb.st.get("active") in (sj or "") and na.st.get("active") not in (sj or "x"), (na.leading, nb.leading, nb.st))

print("\nALL PASSED" if not FAILED else f"\nFAILED: {len(FAILED)}")
sys.exit(1 if FAILED else 0)
