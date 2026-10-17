# Sample output

`sample_report.json` is a real report produced by `mtx.py` against the **local offline
mock** in `tools/mock_routeros.py` (mode `vulnerable`). It exists only to show the JSON
shape — it is **not** a scan of a real device.

Produce your own report with:

```bash
python mtx.py <host> --json report.json
```

Key fields:

| Field | Meaning |
|---|---|
| `tool` | tool identifier |
| `cve` | `CVE-2026-67279` |
| `target` | `host:port` scanned |
| `timestamp_utc` | ISO-8601 UTC time of the run |
| `banner` | SSH identification banner returned by the target |
| `baseline` | reading A — channel attempt with **no** rekey |
| `rekey_test` | reading B — pre-auth rekey, then channel attempt |
| `verdict` | one of `VULNERABLE` / `PATCHED_SIGNATURE` / `NOT_CONFIRMED` / `UNREACHABLE` / `INCONCLUSIVE` |
| `rationale` | human-readable reason for the verdict |
| `safety` | reminder that the run was non-destructive |
