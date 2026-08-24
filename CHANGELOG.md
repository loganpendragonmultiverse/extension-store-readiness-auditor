# Changelog

## 1.1.0 - 2026-08-06

- Added versioned local policy profiles with review dates, source links, store targets, required
  manifest fields and files, severity overrides, and deterministic profile fingerprints.
- Added baseline report comparison for new, resolved, and unchanged findings.
- Embedded policy provenance in JSON and Markdown reports without fetching remote policy content.

## 1.0.0 - 2026-08-03

- Added local audits for extension directories and ZIP, XPI, or CRX packages.
- Added Manifest V3, metadata, icon, permission, host-access, CSP, remote-code, update URL, and package-debris findings for Chrome, Firefox, and Edge review.
- Added deterministic package fingerprints, stable finding codes, Markdown and JSON reports, safe archive limits, replacement-safe output, and CI-friendly exit codes.
