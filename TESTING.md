# Testing

Run `python -m pip install -e ".[dev]"`, then `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m pip_audit`, and `python -m build`.

Tests cover unpacked and archived packages, safe archive paths, root manifests, clean Manifest V3 packages, sensitive permissions, broad hosts, missing assets, executable remote-code patterns, package debris, target validation, output safety, and CLI exit codes. CI repeats formatting, linting, strict typing, tests, dependency audit, and builds across supported operating systems and Python versions.
