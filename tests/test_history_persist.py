#!/usr/bin/env python3
"""SecureMailScope — history persistence across restarts.

Boots its own server on a private port (no external server needed):
  .venv/bin/python tests/test_history_persist.py
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 5177
BASE = f"http://127.0.0.1:{PORT}"

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    ok += cond
    fail += (not cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def call(path, data=None):
    req = urllib.request.Request(BASE + path)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, body) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def boot():
    env = dict(os.environ, PORT=str(PORT))
    p = subprocess.Popen([sys.executable, "app.py"], cwd=ROOT, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/", timeout=1)
            return p
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("server did not come up")


def stop(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()


def main():
    cfg = os.path.join(ROOT, "config")
    hist = os.path.join(cfg, "history.json")
    bak_hist, bak_audit = None, None
    if os.path.isfile(hist):
        shutil.copy2(hist, (bak_hist := hist + ".pretest"))
    if os.path.isfile(os.path.join(cfg, "audit.jsonl")):
        shutil.copy2(os.path.join(cfg, "audit.jsonl"),
                     (bak_audit := os.path.join(cfg, "audit.jsonl.pretest")))
    try:
        for f in (hist, os.path.join(cfg, "audit.jsonl")):
            if os.path.isfile(f):
                os.remove(f)

        # --- session 1: run two analyses, compare them, stop the server ---
        p = boot()
        s, _ = call("/api/analyze", {"scenario_id": "starttls_downgrade"})
        check("session1 analyze downgrade", s == 200, str(s))
        s, _ = call("/api/analyze", {"scenario_id": "secure"})
        check("session1 analyze secure", s == 200, str(s))
        s, h1 = call("/api/history")
        check("session1 two slots", s == 200 and len(h1["history"]) == 2, str(h1))
        s, d = call("/api/compare", {"a": 0, "b": 1})
        check("session1 compare ok", s == 200 and d.get("score_delta") == 100, str(s))
        check("history file written", os.path.isfile(hist))
        on_disk = json.load(open(hist))
        check("history file holds 2 results", isinstance(on_disk, list) and len(on_disk) == 2,
              str(len(on_disk)) if isinstance(on_disk, list) else type(on_disk).__name__)
        stop(p)

        # --- session 2: fresh process restores slots from disk ---
        p = boot()
        s, h2 = call("/api/history")
        check("restart restores slots", s == 200 and len(h2["history"]) == 2, str(h2))
        check("restored sources intact", h2["history"][0]["scenario_id"] == "starttls_downgrade"
              and h2["history"][1]["scenario_id"] == "secure", str(h2["history"]))
        s, d = call("/api/compare", {"a": 0, "b": 1})
        check("compare works across restart", s == 200 and d.get("score_delta") == 100, str(s))
        check("restart compare audited",
              call("/api/settings")[1]["audit"][0]["event"] == "comparison_run")  # trail is newest-first

        # --- bound: 12 max, oldest dropped, file mirrors memory ---
        for _ in range(11):
            call("/api/analyze", {"scenario_id": "secure"})
        s, h3 = call("/api/history")
        check("history bounded at 12", len(h3["history"]) == 12, str(len(h3["history"])))
        check("oldest slot dropped", h3["history"][0]["scenario_id"] == "secure", str(h3["history"][0]))
        check("file mirrors memory", len(json.load(open(hist))) == 12)

        # --- corrupt file is not fatal ---
        stop(p)
        with open(hist, "w") as f:
            f.write("{not json at all")
        p = boot()
        s, h4 = call("/api/history")
        check("corrupt history -> clean empty", s == 200 and h4["history"] == [], str(h4))
        stop(p)

        print(f"\n{ok} passed, {fail} failed")
        return 1 if fail else 0
    finally:
        # leave no test residue: restore pre-test state
        for pth, b in ((hist, bak_hist), (os.path.join(cfg, "audit.jsonl"), bak_audit)):
            try:
                os.remove(pth)
            except OSError:
                pass
            if b:
                shutil.move(b, pth)
        try:
            os.remove(hist + ".tmp")
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
