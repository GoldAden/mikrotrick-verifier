# MikroTrick Verifier

**Non-destructive, behavioral verifier for the MikroTik RouterOS SSH authentication-bypass (CVE-2026-67279) — a.k.a. the MikroTrick chain.**

<p align="center">
  <code>probe. measure. decide. no payload.</code>
</p>

---

## العربية (نظرة سريعة)

أداة صغيرة تفحص **سلوك** جهاز RouterOS تملكه للتأكد عمليًا مما إذا كان البناء المثبَّت
يعاني من تجاوز حالة المصادقة في SSH (المرحلة الأولى من MikroTrick) **قبل** أن تُرقّي.

- فحص **غير تدميري**: لا حسابات، لا كتابة ملفات، لا أوامر إلا مع `--console` (قراءة فقط).
- الحكم **سلوكي** لأن RouterOS لا يُفصح عن إصداره في شعار SSH.
- الدليل الكامل بالعربية: [`docs/GUIDE_AR.md`](docs/GUIDE_AR.md).

### تشغيل سريع على Termux (الأندرويد)

انسخ محتوى [`install_termux.sh`](install_termux.sh) والصقه في Termux، أو نفّذ:

```bash
python mtx.py <عنوان-الجهاز> --port 22
```

> على Termux عادةً يكون الأمر `python` وليس `python3`.

---

## English

### What it does

If a client requests an **SSH key renegotiation (rekey) before authentication**, an
unpatched RouterOS build proceeds to the connection-protocol stage anyway and accepts
opening a **session channel with no login**. The tool measures exactly that, and nothing
more:

| Reading | Patched device | Vulnerable device | Normal SSH (e.g. OpenSSH) |
|---|---|---|---|
| Pre-auth rekey | **fails, connection dropped** | **succeeds** | succeeds |
| Session channel opened pre-auth | — (link already down) | **accepted** | refused |

### Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | Pre-auth session channel accepted — CVE-2026-67279 behaviour. |
| `PATCHED_SIGNATURE` | Pre-auth rekey refused and connection dropped — patched-build signature. |
| `NOT_CONFIRMED` | Rekey allowed but auth enforcement intact — exploitation not proven. |
| `UNREACHABLE` | SSH port not reachable. |
| `INCONCLUSIVE` | Ambiguous reading; review the raw details. |

The verdict is **behavioral** — RouterOS never reveals its version in the SSH banner,
so compare against a **patched control device** to prove the tool discriminates
(see the guide, step 4).

### Install & use

```bash
git clone https://github.com/<you>/mikrotrick-verifier.git
cd mikrotrick-verifier
python -m pip install -r requirements.txt

# 1) offline self-test first (no network, no device)
python tests/selftest_inproc.py      # -> 3/3

# 2) scan your own / authorized device
python mtx.py <host> --port 22 --timeout 8
python mtx.py <host> --json report.json
```

### Safety commitment

- Creates **no** accounts and installs **no** persistence.
- Writes **no** files on the target and changes **no** configuration.
- Runs **no** command on the target unless `--console` is passed explicitly; even then it
  sends a **read-only** command (default `/system resource print`).
- Ships **no** exploit payload — it only measures the server's reaction.

Use only on devices **you own** or are **explicitly authorized in writing** to test.

### Fix & post-exposure audit

1. Upgrade to **6.49.21** (6.x branch) or **7.23.6 / 7.24.3+** (7.x branch).
   Note: **7.24.2** and **7.23.4** are incomplete fixes — do not rely on them.
2. Audit `/user print`, `/system scheduler print`, `/system script print`, SOCKS/tunnels,
   and unknown files on storage.
3. Known IoCs: user `ops`; logs `login failure for user -2 ... via ssh` and
   `user added by ssh:-2@<ip>`; source IPs `82.192.72.4`, `103.102.31.18`.
4. If artefacts are found, treat the device as compromised — Netinstall from clean,
   then restore from a trusted backup.

### Scope note

CVE-2026-67279 affects RouterOS **6.x (6.0.0 – < 6.49.21)** and **7.x**. Full admin
takeover was only reproduced on 7.x (needs companion **CVE-2026-86060**); on 6.x the
bypass enables manipulation of the file namespace. 6.48.6 is in scope (alongside
CVE-2023-30799 / CVE-2023-32154).

---

## Repository layout

```
mikrotrick-verifier/
├── mtx.py                     # single-file, paste-in-place verifier (Termux-friendly)
├── install_termux.sh          # one-paste installer for Termux
├── tools/
│   ├── mikrotrick_check.py    # full-featured verifier (bundled checks, JSON reports)
│   └── mock_routeros.py       # offline SSH mock (vulnerable / patched / normal)
├── tests/
│   ├── selftest_inproc.py     # offline logic self-test  -> 3/3
│   └── test_mtx_cli.py        # end-to-end CLI test      -> 3/3
├── docs/
│   └── GUIDE_AR.md            # full Arabic guide
├── requirements.txt
└── LICENSE
```

## License

MIT — see [LICENSE](LICENSE).
