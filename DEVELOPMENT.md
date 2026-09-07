# Development contract

Provide deterministic, local static evidence for browser-extension store preparation without claiming approval or executing package code.

Preserve bounded archive handling, stable finding codes, explicit store targets, reviewable evidence, replacement-safe output, and the policy-drift limitation. Policy profiles must remain local, versioned, fingerprinted, and operator-authored; never fetch or silently refresh policy content. Baseline comparison must use stable finding evidence and must not treat a prior clean report as proof of marketplace acceptance. Every feature release must update tests, version metadata, changelog, README claims, repository metadata, release artifacts, and the Forge catalog together.

## 1.2.0 improvement session

Add permission-version diffs, declared-versus-observed namespace evidence, policy-age checklists and CRX/XPI container fixtures.

Reports inventory required/optional API and host permissions. Baselines with permission inventories show added/removed declarations; older baselines explicitly report comparison unavailable. JavaScript namespace text patterns include file/line evidence but may match comments or miss dynamic code: absence is not proof of unused permission, and a namespace match is not proof that its permission is needed. --as-of and --policy-max-age (default 90 days) classify the operator-authored policy review date and list sources requiring manual recheck; no policy sources are fetched or refreshed. CRX2/CRX3 header bounds and ZIP payload offsets are validated, with generated CRX/XPI fixtures. Signatures, package authenticity and marketplace acceptance are not verified. Unpacked size limits and symlink rejection preserve bounded local inspection.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.
