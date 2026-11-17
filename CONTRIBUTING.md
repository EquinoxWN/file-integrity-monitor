# Contributing

Thanks for helping. This is a Python project; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+. Caches and virtual environments stay in git-ignored folders inside the repo.

```bash
make setup        # install the package and dev tools
make lint         # ruff, ruff format, mypy --strict
make test         # portable tests on a copy of the fixture host
make test-linux   # real inotify, symlinks and FIFOs (Linux only; CI runs it)
make audit        # known-vulnerability check (as in CI)
make demo         # baseline, live watch and simulated tampering under .tmp/demo
```

A pull request is ready when `make lint` and `make test` pass and CI is green.

## Changing the policy or the fixture host

- The bundled policy is `src/file_integrity_monitor/policies/linux-default.toml`; run
  `fim policy check` after editing it.
- The fixture host is `tests/fixtures/host/` with modes and owners in `.fim-meta/stat.tsv`.
  Tests copy it before changing anything; never edit it from a test. Fixture files stay inert:
  no real keys, password hashes or executable binaries.
- If you add a covered path, update the expected entry counts in `tests/test_tree.py` and
  `tests/test_cli.py`.

## Guidelines

- Keep each change focused; explain the problem it solves in the pull request.
- Add or update a test for every behaviour change, and update `docs/results/` when numbers change.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
