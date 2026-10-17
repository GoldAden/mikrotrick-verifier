# Security Policy & Responsible Use

## Purpose

This repository is a **defensive, non-destructive verification tool** for the MikroTik
RouterOS SSH authentication bypass (CVE-2026-67279, the "MikroTrick" chain).

It only **measures how a server reacts** to a pre-authentication key renegotiation and to
an unauthenticated session-channel request. It does **not** carry an exploit payload.

## What the tool never does

- No account creation, no credential changes.
- No file writes or configuration changes on the target.
- No persistence, backdoor, tunnel, or scheduled task is installed.
- No command is executed on the target unless `--console` is passed explicitly, and even
  then only a read-only command is sent (default: `/system resource print`).

## Authorized use only

Run this tool **only** against systems you own or for which you hold **explicit written
authorization** to test. Testing third-party infrastructure without authorization may be
unlawful in your jurisdiction.

## Reporting a vulnerability

If you find a problem in **this tool** (e.g. a crash, a false verdict, or any behaviour
that violates the safety commitments above), please open a private security advisory on
GitHub or contact the maintainer. Do not open a public issue for security-relevant
findings.

For MikroTik product vulnerabilities, report to MikroTik / MITRE per their processes.

## Reference data

- **In scope:** RouterOS 6.x (6.0.0 – < 6.49.21) and 7.x.
- **Companion issue for full admin takeover on 7.x:** CVE-2026-86060.
- **Fixed in:** 6.49.21 (6.x) · 7.23.6 / 7.24.3+ (7.x). **7.24.2** and **7.23.4** are
  incomplete fixes.
- **Indicators of compromise:** user `ops`; log lines `login failure for user -2 ... via
  ssh` and `user added by ssh:-2@<ip>`; source IPs `82.192.72.4`, `103.102.31.18`.
