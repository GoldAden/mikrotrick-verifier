# -*- coding: utf-8 -*-
"""
selftest_inproc.py
------------------
Self-contained, OFFLINE self-test.

It spins up an in-process SSH mock (thread) for each of three behaviours,
then calls the detection logic directly and asserts the verdict matches.

No real device is needed. Nothing is exposed beyond 127.0.0.1.

    python tests/selftest_inproc.py

Expected: 3/3
"""

import logging
import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, ROOT)

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

import paramiko
from paramiko import RSAKey

import mock_routeros as mk
import mikrotrick_check as mc

HOST = "127.0.0.1"


def free_port():
    s = socket.socket()
    s.bind((HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_server(mode, port, host_key, stop_flag):
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((HOST, port))
    lsock.listen(16)
    lsock.settimeout(0.3)

    def worker(csock):
        try:
            cls = {
                "vulnerable": mk.VulnerableTransport,
                "patched": mk.PatchedTransport,
                "normal": paramiko.Transport,
            }[mode]
            t = cls(csock)
            t.add_server_key(host_key)
            t.start_server(server=mk.HarnessServer())
            end = time.time() + 10
            while t.is_active() and time.time() < end and not stop_flag.is_set():
                time.sleep(0.2)
            t.close()
        except Exception:
            pass
        finally:
            try:
                csock.close()
            except Exception:
                pass

    def loop():
        while not stop_flag.is_set():
            try:
                csock, _ = lsock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(target=worker, args=(csock,), daemon=True).start()
        try:
            lsock.close()
        except Exception:
            pass

    threading.Thread(target=loop, daemon=True).start()
    return lsock


def main():
    host_key = RSAKey.generate(2048)
    cases = [
        ("vulnerable", mc.VERDICT_VULNERABLE),
        ("patched", mc.VERDICT_PATCHED_REKEY),
        ("normal", mc.VERDICT_NOT_CONFIRMED),
    ]
    passes = 0
    print("=" * 70)
    print(" MikroTrick detection logic -- offline self-test")
    print("=" * 70)

    for mode, expect in cases:
        port = free_port()
        stop = threading.Event()
        start_server(mode, port, host_key, stop)
        time.sleep(0.5)

        print("\n--- mock mode: %s | expected: %s ---" % (mode, expect))
        base = mc.probe_baseline(HOST, port, 6.0)
        rk = mc.probe_rekey(HOST, port, 6.0, console=False)
        verdict, why = mc.decide(base, rk)

        print("    baseline: connected=%s channel=%s err=%s"
              % (base.connected, base.channel_opened, base.channel_error or "-"))
        print("    rekey   : connected=%s rekey_ok=%s err=%s channel=%s err=%s"
              % (rk.connected, rk.rekey_ok, rk.rekey_error or "-",
                 rk.channel_opened, rk.channel_error or "-"))
        print("    >> verdict: %s" % verdict)
        ok = (verdict == expect)
        print("    >> %s" % ("PASS" if ok else "FAIL"))
        if ok:
            passes += 1

        stop.set()
        time.sleep(0.3)

    print("\n" + "=" * 70)
    print(" RESULT: %d/%d passed" % (passes, len(cases)))
    print("=" * 70)
    print("\nVerdict meanings:")
    print("  VULNERABLE        -> session channel accepted pre-auth after rekey (risk)")
    print("  PATCHED_SIGNATURE -> pre-auth rekey refused = patched build signature")
    print("  NOT_CONFIRMED     -> rekey ok but channel refused = healthy server")
    return 0 if passes == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
