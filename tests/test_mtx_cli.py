# -*- coding: utf-8 -*-
"""
End-to-end CLI test for mtx.py (the single-file Termux tool).

Runs the real CLI against the in-process mock in all three modes and
checks the emitted JSON verdict.

    python tests/test_mtx_cli.py

Expected: TOTAL: 3/3
"""

import json
import logging
import os
import socket
import sys
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, ROOT)

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

import paramiko
from paramiko import RSAKey

import mock_routeros as mk
import mtx

HOST = "127.0.0.1"
key = RSAKey.generate(2048)


def serve(mode, port, stop):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((HOST, port))
    ls.listen(16)
    ls.settimeout(0.3)

    def worker(cs):
        try:
            cls = {"vulnerable": mk.VulnerableTransport, "patched": mk.PatchedTransport,
                   "normal": paramiko.Transport}[mode]
            t = cls(cs)
            t.add_server_key(key)
            t.start_server(server=mk.HarnessServer())
            end = time.time() + 15
            while t.is_active() and time.time() < end and not stop.is_set():
                time.sleep(0.2)
            t.close()
        except Exception as e:
            print("   [worker %s] %s: %s" % (mode, type(e).__name__, e), flush=True)
        finally:
            try:
                cs.close()
            except Exception:
                pass

    def loop():
        while not stop.is_set():
            try:
                cs, _ = ls.accept()
            except socket.timeout:
                continue
            except Exception as e:
                print("   [LOOP %s] %s: %s" % (mode, type(e).__name__, e), flush=True)
                traceback.print_exc()
                break
            threading.Thread(target=worker, args=(cs,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


results = []
for mode, exp in [("vulnerable", "VULNERABLE"), ("patched", "PATCHED_SIGNATURE"),
                  ("normal", "NOT_CONFIRMED")]:
    s = socket.socket()
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    stop = threading.Event()
    serve(mode, port, stop)
    time.sleep(0.6)
    jf = os.path.join(ROOT, "examples", "report_%s.json" % mode)
    os.makedirs(os.path.dirname(jf), exist_ok=True)
    sys.argv = ["mtx.py", HOST, "--port", str(port), "--timeout", "6", "--json", jf]
    rc = mtx.main()
    got = json.load(open(jf))["verdict"]
    ok = got == exp
    results.append(ok)
    print("%-11s exp=%-18s got=%-18s %s (rc=%d)"
          % (mode, exp, got, "PASS" if ok else "FAIL", rc), flush=True)
    stop.set()
    time.sleep(0.4)

print("TOTAL: %d/%d" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
