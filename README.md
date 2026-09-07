# Extension Store Readiness Auditor

[![CI](https://github.com/loganpendragonmultiverse/extension-store-readiness-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/loganpendragonmultiverse/extension-store-readiness-auditor/actions/workflows/ci.yml)

Audit an unpacked browser extension or ZIP/XPI/CRX package for review risks shared by the Chrome Web Store, Firefox Add-ons, and Microsoft Edge Add-ons. The local CLI validates the package boundary, Manifest V3 metadata, declared icons, sensitive permissions, broad host access, executable remote-code patterns, unsafe content-security-policy values, custom update URLs, and development debris. Versioned local policy profiles make additional store requirements and their provenance explicit without silently changing the built-in checks.

## Three-minute start

```bash
python -m pip install .
extension-store-audit path/to/extension.zip
extension-store-audit path/to/unpacked --target chrome --target edge --format json --output audit.json
extension-store-audit path/to/extension.zip --policy examples/policy-profile.json --format json --output current.json
extension-store-audit path/to/extension.zip --policy examples/policy-profile.json --baseline previous.json
```

Exit code `0` means no static errors, `1` means the report contains errors requiring correction, and `2` means the package or command could not be analyzed. Existing reports are never overwritten.

## Outputs

Every finding has a stable code, severity, evidence location, and affected store targets. The report also records a deterministic package fingerprint without copying package contents into the report. When `--policy` is supplied, the report binds the policy ID, review date, source links, targets, and complete policy content through a SHA-256 fingerprint. `--baseline` compares finding identities and reports new, resolved, and unchanged results. Markdown is intended for human review; JSON is suitable for CI evidence.

Policy profiles use schema version 1. They can require manifest paths or package files per store and can change the severity of a stable finding code. Profiles are operator-maintained evidence snapshots: source links are recorded but never contacted, and a review date does not prove that the profile is current or complete. See [the example profile](examples/policy-profile.json).

## Privacy and security

Everything runs locally. The auditor does not upload packages, execute extension code, contact URLs found in the package or policy profile, use telemetry, or require an account. ZIP paths, duplicate names, file counts, and uncompressed sizes are checked before analysis.

## Limitations

The checks are conservative static heuristics, not legal advice or a guarantee of marketplace acceptance. Store policies and reviewer practices change. A policy profile is only as accurate as its sources, review date, and operator-authored requirements. Permission usage cannot always be proven from bundled code, minified code can reduce evidence quality, and a clean report does not replace current policy review, functional testing, privacy disclosures, screenshots, reviewer credentials, or human inspection.

## Development

```bash
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
mypy src
pytest
python -m pip_audit
python -m build
```

Python 3.10 or newer is supported on Windows, macOS, and Linux. Part of the [Logan Pendragon Forge open-source collection](https://www.loganpendragonforge.com/open-source/). Licensed under the [MIT License](LICENSE).

## Version 1.2.0: reviewed improvements

Add permission-version diffs, declared-versus-observed namespace evidence, policy-age checklists and CRX/XPI container fixtures.

```bash
extension-store-audit ./extension --policy policy.json --as-of 2026-09-07 --baseline previous.json --format json --output review.json
```

Reports inventory required/optional API and host permissions. Baselines with permission inventories show added/removed declarations; older baselines explicitly report comparison unavailable. JavaScript namespace text patterns include file/line evidence but may match comments or miss dynamic code: absence is not proof of unused permission, and a namespace match is not proof that its permission is needed. --as-of and --policy-max-age (default 90 days) classify the operator-authored policy review date and list sources requiring manual recheck; no policy sources are fetched or refreshed. CRX2/CRX3 header bounds and ZIP payload offsets are validated, with generated CRX/XPI fixtures. Signatures, package authenticity and marketplace acceptance are not verified. Unpacked size limits and symlink rejection preserve bounded local inspection.
