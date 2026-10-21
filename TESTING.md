# Testing

Run `python -m pip install -e ".[dev]"`, then `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m pip_audit`, and `python -m build`.

Tests cover unpacked and archived packages, safe archive paths, root manifests, clean Manifest V3 packages, sensitive permissions, broad hosts, missing assets, executable remote-code patterns, package debris, target validation, policy validation and fingerprints, per-store requirements, severity overrides, baseline comparison, output safety, and CLI exit codes. CI repeats formatting, linting, strict typing, tests, dependency audit, and builds across supported operating systems and Python versions.

## 1.2.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Add permission-version diffs, declared-versus-observed namespace evidence, policy-age checklists and CRX/XPI container fixtures.

## 1.3.0 — 2026-10-16

Use synthetic directory, ZIP, XPI and CRX fixtures for complete and missing entrypoints, malformed containers and values, escaping/absolute/remote references and source preservation. Run existing policy, permission, archive and CLI tests.

The popup matrix covers omitted, empty, existing, missing and non-string declarations for action, browser_action and page_action across directories, ZIP, XPI and CRX containers.

## 1.4.1 — bounded package and target-specific review

Built-in store-version checks are an explicitly dated 2026-10-21 snapshot for **new submissions**. Firefox accepts Manifest V2 or V3; Chrome and Edge new submissions require V3. Version strings use one to four unpadded numeric components: Firefox's documented maximum is nine digits per component, while the Chromium checks cap components at 65535 and reject all-zero versions. Mixed-target findings name only affected targets. These checks are not a complete manifest schema, runtime test, store-policy refresh or approval guarantee. Existing Edge MV2 updates and enterprise/browser support schedules are outside the new-submission model.

The snapshot sources are [Chrome version rules](https://developer.chrome.com/docs/extensions/reference/manifest/version), [Chrome MV2 timeline](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline), [Mozilla version rules](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/version), [Mozilla MV2/MV3 support](https://blog.mozilla.org/en/firefox/firefox-manifest-v3-adblockers/) and [Edge's new-submission timeline](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/manifest-v3). Recheck official sources before submission. User-authored policy files retain their own review date and fingerprint; the tool never fetches policy sources or silently updates a profile.

Background pages/scripts receive the same local-member checks as other declared entrypoints. Optional permission/host declarations have shape errors and potential-risk warnings; no grant or execution is inferred. Archives reject ambiguous/colliding names, symlink/special members and encryption; unpacked roots and path components cannot be symlinks. Inspection remains limited to 20,000 directory/archive entries and 500 MiB of package bytes. Manifest, profile and baseline JSON is limited to 10 MiB, 128 nesting levels and 1,000-digit integers; duplicate keys and nonfinite numbers are errors.

Baselines require explicit findings and a valid selected target scope. Comparisons use only shared targets; current-only and baseline-only targets remain explicit and are not classified as new or resolved. Disjoint targets make comparison unavailable. Malformed or duplicate finding identities are rejected rather than silently treated as resolved. Legacy reports without permission inventories still report that comparison unavailable. New report files use exclusive creation and reject symlinks; accidental replacement is prevented without claiming hostile concurrent filesystem protection. Markdown evidence and policy IDs are rendered literally.

Installed examples are under `share/doc/extension-store-readiness-auditor/examples` in the installation prefix. Audit that directory for a small offline demonstration; it intentionally has no icon, producing a review warning rather than referencing a nonexistent asset. It is a static auditor fixture, not an extension runtime acceptance claim.

Executable CSP heuristics inspect extension-page script, worker, object and fallback directives. Explicit image/connection destinations and the separate sandbox policy do not alone count as executable extension-page evidence. This is not full browser CSP evaluation. Root manifest spelling must be exactly `manifest.json`.

Malformed archive fixtures preserve exact stored member names on every host OS; assertions check raw ZIP bytes and original names before expecting rejection.

Complete ZIP members are validated from their raw compressed spans, including stream end, actual size and CRC; directory members must decode to zero bytes. Stored, Deflate, BZIP2 and LZMA remain supported, with Zstandard when the Python standard library provides it. Codec dictionaries/windows are capped at 512 MiB in addition to the existing container and aggregate decoded limits.

## 1.4.2: Release artifact verification

The tag workflow checks that the stable tag, project metadata and runtime version agree before building. It runs the full existing quality suite and dependency audit, verifies wheel and source-distribution metadata, and writes SHA256SUMS from those exact two payloads. Native PR/main checks and independent installed-artifact acceptance remain required before publication. This maintenance release preserves runtime behavior and supported Python versions.
