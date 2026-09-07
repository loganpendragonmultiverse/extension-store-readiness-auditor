# Testing

Run `python -m pip install -e ".[dev]"`, then `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m pip_audit`, and `python -m build`.

Tests cover unpacked and archived packages, safe archive paths, root manifests, clean Manifest V3 packages, sensitive permissions, broad hosts, missing assets, executable remote-code patterns, package debris, target validation, policy validation and fingerprints, per-store requirements, severity overrides, baseline comparison, output safety, and CLI exit codes. CI repeats formatting, linting, strict typing, tests, dependency audit, and builds across supported operating systems and Python versions.

## 1.2.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Add permission-version diffs, declared-versus-observed namespace evidence, policy-age checklists and CRX/XPI container fixtures.
