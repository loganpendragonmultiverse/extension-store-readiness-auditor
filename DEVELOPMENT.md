# Development contract

Provide deterministic, local static evidence for browser-extension store preparation without claiming approval or executing package code.

Preserve bounded archive handling, stable finding codes, explicit store targets, reviewable evidence, replacement-safe output, and the policy-drift limitation. Policy profiles must remain local, versioned, fingerprinted, and operator-authored; never fetch or silently refresh policy content. Baseline comparison must use stable finding evidence and must not treat a prior clean report as proof of marketplace acceptance. Every feature release must update tests, version metadata, changelog, README claims, repository metadata, release artifacts, and the Forge catalog together.

## 1.2.0 improvement session

Add permission-version diffs, declared-versus-observed namespace evidence, policy-age checklists and CRX/XPI container fixtures.

Reports inventory required/optional API and host permissions. Baselines with permission inventories show added/removed declarations; older baselines explicitly report comparison unavailable. JavaScript namespace text patterns include file/line evidence but may match comments or miss dynamic code: absence is not proof of unused permission, and a namespace match is not proof that its permission is needed. --as-of and --policy-max-age (default 90 days) classify the operator-authored policy review date and list sources requiring manual recheck; no policy sources are fetched or refreshed. CRX2/CRX3 header bounds and ZIP payload offsets are validated, with generated CRX/XPI fixtures. Signatures, package authenticity and marketplace acceptance are not verified. Unpacked size limits and symlink rejection preserve bounded local inspection.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.

## 1.3.0 — 2026-10-16

Checks cover `background.service_worker`, content-script `js` and `css` arrays, `action`, `browser_action` and `page_action` popups, `options_page`, `options_ui.page` and `devtools_page`. Stable errors `entrypoint-shape`, `entrypoint-path` and `entrypoint-missing` point to the manifest field. Nonempty references must be exact relative member paths. Popup fields may be omitted or set to an empty string, which means no popup; other declared entrypoints must be nonempty. Absolute paths, traversal, backslashes, URL schemes, queries/fragments, percent-encoded ambiguity and control characters are rejected. No JavaScript imports are resolved, no entrypoint code runs, no external files are read, and no URLs are fetched. This verifies declared membership only, not runtime behavior or marketplace acceptance.

Popup compatibility is backed by Chromium's parameterized [EmptyDefaultPopup regression](https://chromium.googlesource.com/chromium/src/+/0fda5ad17555ca8e1d06b585587ea021b8a10918/extensions/common/manifest_handlers/extension_action_handler_unittest.cc#362) for action, browser_action and page_action. Null and non-string popup values remain malformed; nonempty missing paths remain errors.

## 1.4.0 — bounded package and target-specific review

Built-in store-version checks are an explicitly dated 2026-10-21 snapshot for **new submissions**. Firefox accepts Manifest V2 or V3; Chrome and Edge new submissions require V3. Version strings use one to four unpadded numeric components: Firefox's documented maximum is nine digits per component, while the Chromium checks cap components at 65535 and reject all-zero versions. Mixed-target findings name only affected targets. These checks are not a complete manifest schema, runtime test, store-policy refresh or approval guarantee. Existing Edge MV2 updates and enterprise/browser support schedules are outside the new-submission model.

The snapshot sources are [Chrome version rules](https://developer.chrome.com/docs/extensions/reference/manifest/version), [Chrome MV2 timeline](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline), [Mozilla version rules](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/version), [Mozilla MV2/MV3 support](https://blog.mozilla.org/en/firefox/firefox-manifest-v3-adblockers/) and [Edge's new-submission timeline](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/manifest-v3). Recheck official sources before submission. User-authored policy files retain their own review date and fingerprint; the tool never fetches policy sources or silently updates a profile.

Background pages/scripts receive the same local-member checks as other declared entrypoints. Optional permission/host declarations have shape errors and potential-risk warnings; no grant or execution is inferred. Archives reject ambiguous/colliding names, symlink/special members and encryption; unpacked roots and path components cannot be symlinks. Inspection remains limited to 20,000 directory/archive entries and 500 MiB of package bytes. Manifest, profile and baseline JSON is limited to 10 MiB, 128 nesting levels and 1,000-digit integers; duplicate keys and nonfinite numbers are errors.

Baselines require explicit findings and a valid selected target scope. Comparisons use only shared targets; current-only and baseline-only targets remain explicit and are not classified as new or resolved. Disjoint targets make comparison unavailable. Malformed or duplicate finding identities are rejected rather than silently treated as resolved. Legacy reports without permission inventories still report that comparison unavailable. New report files use exclusive creation and reject symlinks; accidental replacement is prevented without claiming hostile concurrent filesystem protection. Markdown evidence and policy IDs are rendered literally.

Installed examples are under `share/doc/extension-store-readiness-auditor/examples` in the installation prefix. Audit that directory for a small offline demonstration; it intentionally has no icon, producing a review warning rather than referencing a nonexistent asset. It is a static auditor fixture, not an extension runtime acceptance claim.

Executable CSP heuristics inspect extension-page script, worker, object and fallback directives. Explicit image/connection destinations and the separate sandbox policy do not alone count as executable extension-page evidence. This is not full browser CSP evaluation. Root manifest spelling must be exactly `manifest.json`.
