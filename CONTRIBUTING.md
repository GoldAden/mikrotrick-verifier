# Contributing

Thanks for helping make this verifier more reliable.

## Ground rules

This repository stays **defensive and non-destructive**. Pull requests that add exploit
payloads, credential creation, persistence, tunnels, or any write action against a target
will be closed.

## Before you open a PR

1. Run the offline self-tests — both must pass:

   ```bash
   python tests/selftest_inproc.py   # -> RESULT: 3/3 passed
   python tests/test_mtx_cli.py      # -> TOTAL: 3/3
   ```

2. Keep sources importable with only `paramiko` as a third-party dependency.
3. Keep the code free of hard-coded absolute paths so the tests run from a fresh clone.
4. If you change detection logic, also update the verdict table in `README.md` and the
   meanings printed at the end of the self-test.

## Reporting a defect

For anything security-relevant in this tool, use GitHub's private security advisory
rather than a public issue. See [`SECURITY.md`](SECURITY.md).
