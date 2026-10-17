#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mock_routeros.py
-----------------
محاكي تعليمي لخدمة SSH على غرار RouterOS، لاختبار منطق الأداة mikrotrick_check.py
محليًا (بدون أي جهاز حقيقي، وبدون أي حِمل هجومي).

الأوضاع الثلاثة:
  --mode vulnerable : يحاكي السلوك غير المُرقَّع — يقبل إعادة التفاوض قبل المصادقة
                      ثم يسمح بفتح قناة جلسة بلا مصادقة. (لاختبار المنطق فقط)
  --mode patched    : يحاكي السلوك المُرقَّع — يرفض إعادة التفاوض قبل المصادقة
                      ويقطع الاتصال. (يجب أن تُصنّف PATCHED_SIGNATURE)
  --mode normal     : يحاكي خادمًا عاديًا — يسمح بإعادة التفاوض لكن يرفض القناة
                      بلا مصادقة. (يجب أن تُصنّف NOT_CONFIRMED)

ما لا يفعله هذا الملف: لا يُنشئ حسابات، ولا يُنفّذ أوامر، ولا يحاكي حقن واصف
الملفات أو CVE-2026-86060. الغرض منه اختبار سلامة منطق الكشف فقط.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
import time

import paramiko
from paramiko import RSAKey, ServerInterface, Transport, AUTH_SUCCESSFUL, OPEN_SUCCEEDED


class HarnessServer(ServerInterface):
    """خادم بسيط: يقبل أي مصادقة كلمة مرور (لبيئة مختبر فقط)."""

    def check_auth_password(self, username, password):  # noqa: D102
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):  # noqa: D102
        return OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a, **kw):  # noqa: D102
        return True

    def check_channel_shell_request(self, channel):  # noqa: D102
        return True

    def check_channel_exec_request(self, channel, command):  # noqa: D102
        return True

    def get_allowed_auths(self, username):  # noqa: D102
        return "password,publickey"


class VulnerableTransport(Transport):
    """يحاكي الخلل: يقبل رسائل طبقة الاتصال بلا مصادقة (كما في البناء غير المُرقَّع)."""

    def _ensure_authed(self, ptype, message):  # noqa: D102
        return None


class PatchedTransport(Transport):
    """يحاكي الإصلاح: يرفض *إعادة* التفاوض قبل المصادقة.

    ملاحظة مهمة: التفاوض الأولي (initial kex) يحدث أصلاً قبل المصادقة، لذا
    لا يجوز رفضه. المعيار الصحيح هو: طلب تفاوض جديد بعد اكتمال التفاوض
    الأولي بينما الجلسة ما زالت غير مُصادَقة = سلوك شاذ → يُرفض ويُقطع الاتصال.
    """

    def _parse_kex_init(self, m):  # noqa: D102
        if self.initial_kex_done and not self.is_authenticated():
            self._log(paramiko.common.ERROR, "pre-auth rekey rejected (patched behavior)")
            raise paramiko.SSHException("pre-auth rekey rejected")
        return super()._parse_kex_init(m)


def _serve(host: str, port: int, mode: str, host_key: RSAKey) -> None:
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, port))
    lsock.listen(16)
    print(f"[mock] listening on {host}:{port} mode={mode}", flush=True)

    while True:
        try:
            csock, addr = lsock.accept()
        except KeyboardInterrupt:
            break

        print(f"[mock] connection from {addr[0]}:{addr[1]}", flush=True)

        def handle(csock=csock):
            try:
                cls = {
                    "vulnerable": VulnerableTransport,
                    "patched": PatchedTransport,
                    "normal": Transport,
                }[mode]
                t = cls(csock)
                t.add_server_key(host_key)
                t.start_server(server=HarnessServer())
                # أبقِ الجلسة مفتوحة لمدة قصيرة ليكمل العميل فحوصه
                end = time.time() + 12
                while t.is_active() and time.time() < end:
                    time.sleep(0.2)
                t.close()
            except Exception as exc:  # pragma: no cover
                print(f"[mock] handler error: {type(exc).__name__}: {exc}", flush=True)
            finally:
                try:
                    csock.close()
                except Exception:
                    pass

        threading.Thread(target=handle, daemon=True).start()


def main() -> int:
    # إسكات سجلات الطبقة الدنيا لتبقى المخرجات نظيفة ومقروءة
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    ap = argparse.ArgumentParser(description="محاكي SSH لاختبار منطق كشف CVE-2026-67279")
    ap.add_argument("--mode", choices=["vulnerable", "patched", "normal"], required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--key", default="", help="ملف مفتاح مضيف RSA (يُنشأ تلقائيًا إن لم يوجد)")
    args = ap.parse_args()

    key_path = args.key or f"mock_hostkey_{args.mode}"
    try:
        host_key = RSAKey(filename=key_path)
    except Exception:
        host_key = RSAKey.generate(2048)
        host_key.write_private_key_file(key_path)
        print(f"[mock] generated host key: {key_path}", flush=True)

    try:
        _serve(args.host, args.port, args.mode, host_key)
    except KeyboardInterrupt:
        print("\n[mock] stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
