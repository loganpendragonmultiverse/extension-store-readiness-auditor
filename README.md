# Extension Store Readiness Auditor

[![CI](https://github.com/loganpendragonmultiverse/extension-store-readiness-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/loganpendragonmultiverse/extension-store-readiness-auditor/actions/workflows/ci.yml)

Audit an unpacked browser extension or ZIP/XPI/CRX package for review risks shared by the Chrome Web Store, Firefox Add-ons, and Microsoft Edge Add-ons. The local CLI validates the package boundary, target-specific manifest metadata, declared icons, sensitive permissions, broad host access, executable remote-code patterns, unsafe content-security-policy values, custom update URLs, and development debris. Versioned local policy profiles make additional store requirements and their provenance explicit without silently changing the built-in checks.

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


## 1.3.0 — 2026-10-16: Local entrypoint validation

Validate declared local extension entrypoints against the bounded package inventory.

Checks cover `background.service_worker`, content-script `js` and `css` arrays, `action`, `browser_action` and `page_action` popups, `options_page`, `options_ui.page` and `devtools_page`. Stable errors `entrypoint-shape`, `entrypoint-path` and `entrypoint-missing` point to the manifest field. Nonempty references must be exact relative member paths. Popup fields may be omitted or set to an empty string, which means no popup; other declared entrypoints must be nonempty. Absolute paths, traversal, backslashes, URL schemes, queries/fragments, percent-encoded ambiguity and control characters are rejected. No JavaScript imports are resolved, no entrypoint code runs, no external files are read, and no URLs are fetched. This verifies declared membership only, not runtime behavior or marketplace acceptance.

## 1.4.1 — bounded package and target-specific review

Built-in store-version checks are an explicitly dated 2026-10-21 snapshot for **new submissions**. Firefox accepts Manifest V2 or V3; Chrome and Edge new submissions require V3. Version strings use one to four unpadded numeric components: Firefox's documented maximum is nine digits per component, while the Chromium checks cap components at 65535 and reject all-zero versions. Mixed-target findings name only affected targets. These checks are not a complete manifest schema, runtime test, store-policy refresh or approval guarantee. Existing Edge MV2 updates and enterprise/browser support schedules are outside the new-submission model.

The snapshot sources are [Chrome version rules](https://developer.chrome.com/docs/extensions/reference/manifest/version), [Chrome MV2 timeline](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline), [Mozilla version rules](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/version), [Mozilla MV2/MV3 support](https://blog.mozilla.org/en/firefox/firefox-manifest-v3-adblockers/) and [Edge's new-submission timeline](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/manifest-v3). Recheck official sources before submission. User-authored policy files retain their own review date and fingerprint; the tool never fetches policy sources or silently updates a profile.

Background pages/scripts receive the same local-member checks as other declared entrypoints. Optional permission/host declarations have shape errors and potential-risk warnings; no grant or execution is inferred. Archives reject ambiguous/colliding names, symlink/special members and encryption; unpacked roots and path components cannot be symlinks. Inspection remains limited to 20,000 directory/archive entries and 500 MiB of package bytes. Manifest, profile and baseline JSON is limited to 10 MiB, 128 nesting levels and 1,000-digit integers; duplicate keys and nonfinite numbers are errors.

Baselines require explicit findings and a valid selected target scope. Comparisons use only shared targets; current-only and baseline-only targets remain explicit and are not classified as new or resolved. Disjoint targets make comparison unavailable. Malformed or duplicate finding identities are rejected rather than silently treated as resolved. Legacy reports without permission inventories still report that comparison unavailable. New report files use exclusive creation and reject symlinks; accidental replacement is prevented without claiming hostile concurrent filesystem protection. Markdown evidence and policy IDs are rendered literally.

Installed examples are under `share/doc/extension-store-readiness-auditor/examples` in the installation prefix. Audit that directory for a small offline demonstration; it intentionally has no icon, producing a review warning rather than referencing a nonexistent asset. It is a static auditor fixture, not an extension runtime acceptance claim.

Executable CSP heuristics inspect extension-page script, worker, object and fallback directives. Explicit image/connection destinations and the separate sandbox policy do not alone count as executable extension-page evidence. This is not full browser CSP evaluation. Root manifest spelling must be exactly `manifest.json`.

Complete ZIP members are validated from their raw compressed spans, including stream end, actual size and CRC; directory members must decode to zero bytes. Stored, Deflate, BZIP2 and LZMA remain supported, with Zstandard when the Python standard library provides it. Codec dictionaries/windows are capped at 512 MiB in addition to the existing container and aggregate decoded limits.
