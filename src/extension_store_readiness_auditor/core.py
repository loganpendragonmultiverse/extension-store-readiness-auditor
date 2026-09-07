from __future__ import annotations

import hashlib
import json
import re
import struct
import zipfile
from collections.abc import Iterable
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from .review import permission_review, policy_review

PROJECT = "extension-store-readiness-auditor"
TARGETS = {"chrome", "firefox", "edge"}
HIGH_RISK_PERMISSIONS = {
    "cookies",
    "debugger",
    "downloads.open",
    "geolocation",
    "history",
    "management",
    "nativeMessaging",
    "privacy",
    "proxy",
    "webRequestBlocking",
}
REMOTE_CODE = re.compile(
    r"(?:eval\s*\(|new\s+Function\s*\(|importScripts\s*\(\s*['\"]https?://|"
    r"import\s*\(\s*['\"]https?://)",
    re.IGNORECASE,
)
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){0,3}$")
MAX_FILES = 20_000
MAX_UNCOMPRESSED = 500 * 1024 * 1024


def _finding(
    severity: str, code: str, message: str, evidence: str, targets: Iterable[str]
) -> dict[str, Any]:
    return {
        "severity": severity,
        "code": code,
        "message": message,
        "evidence": evidence,
        "targets": sorted(targets),
    }


def _safe_name(name: str) -> str:
    normalized = PurePosixPath(name.replace("\\", "/"))
    if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
        raise ValueError(f"unsafe package member path: {name}")
    return normalized.as_posix()


def _read_package(source: Path) -> tuple[dict[str, bytes], str]:
    source = source.resolve()
    if source.is_dir():
        files: dict[str, bytes] = {}
        total = 0
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError("package symlinks are unsupported")
            if path.is_file():
                total += path.stat().st_size
                if total > MAX_UNCOMPRESSED:
                    raise ValueError("package exceeds the uncompressed-size limit")
                relative = path.relative_to(source).as_posix()
                files[relative] = path.read_bytes()
                if len(files) > MAX_FILES:
                    raise ValueError("package exceeds the file-count limit")
        return files, str(source)
    if source.is_file() and source.suffix.casefold() in {".zip", ".xpi", ".crx"}:
        files = {}
        if source.stat().st_size > MAX_UNCOMPRESSED:
            raise ValueError("package container exceeds the size limit")
        if source.suffix.casefold() == ".crx":
            with source.open("rb") as handle:
                header = handle.read(16)
                if len(header) < 12 or header[:4] != b"Cr24":
                    raise ValueError("invalid CRX header")
                version = struct.unpack("<I", header[4:8])[0]
                if version == 3:
                    offset = 12 + struct.unpack("<I", header[8:12])[0]
                elif version == 2 and len(header) == 16:
                    public, signature = struct.unpack("<II", header[8:16])
                    offset = 16 + public + signature
                else:
                    raise ValueError("unsupported CRX version")
                if offset > 16 * 1024 * 1024 or offset >= source.stat().st_size:
                    raise ValueError("invalid CRX header length")
                handle.seek(offset)
                if handle.read(4) != b"PK\x03\x04":
                    raise ValueError("CRX payload is not a ZIP archive")
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_FILES:
                raise ValueError("package exceeds the file-count limit")
            if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED:
                raise ValueError("package exceeds the uncompressed-size limit")
            for info in infos:
                if info.is_dir():
                    continue
                name = _safe_name(info.filename)
                key = name.casefold()
                if any(existing.casefold() == key for existing in files):
                    raise ValueError(f"duplicate package member path: {name}")
                files[name] = archive.read(info)
        return files, str(source)
    raise ValueError("source must be an extension directory or ZIP, XPI, or CRX archive")


def _manifest(files: dict[str, bytes]) -> dict[str, Any]:
    candidates = [name for name in files if name.casefold() == "manifest.json"]
    if not candidates:
        nested = [name for name in files if PurePosixPath(name).name.casefold() == "manifest.json"]
        if nested:
            raise ValueError("manifest.json must be at the package root")
        raise ValueError("manifest.json is missing")
    try:
        data = json.loads(files[candidates[0]].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"manifest.json is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TypeError("manifest.json must contain an object")
    return data


def load_policy(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("policy profile must be a schema version 1 object")
    profile_id = data.get("id")
    if not isinstance(profile_id, str) or not profile_id.strip():
        raise ValueError("policy profile requires an id")
    reviewed_at = data.get("reviewed_at")
    if not isinstance(reviewed_at, str):
        raise TypeError("policy profile requires a reviewed_at date")
    try:
        date.fromisoformat(reviewed_at)
    except ValueError as exc:
        raise ValueError("policy profile reviewed_at must be an ISO date") from exc
    targets = data.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or not all(isinstance(target, str) for target in targets)
        or not set(targets) <= TARGETS
    ):
        raise ValueError(f"policy targets must be selected from: {', '.join(sorted(TARGETS))}")
    sources = data.get("sources", [])
    if not isinstance(sources, list):
        raise TypeError("policy sources must be a list")
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("url"), str):
            raise TypeError("policy source must contain a URL")
        parsed = urlparse(source["url"])
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("policy source URL must use HTTP or HTTPS")
        if "title" in source and not isinstance(source["title"], str):
            raise TypeError("policy source title must be text")
    for key in ("required_manifest_fields", "required_files"):
        value = data.get(key, {})
        if not isinstance(value, dict) or not set(value) <= TARGETS:
            raise ValueError(f"{key} must map known targets to lists")
        for target, requirements in value.items():
            if not isinstance(requirements, list) or not all(
                isinstance(requirement, str) and requirement.strip() for requirement in requirements
            ):
                raise TypeError(f"{key}.{target} must be a string list")
            if key == "required_files":
                for requirement in requirements:
                    if _safe_name(requirement) != requirement.replace("\\", "/"):
                        raise ValueError(
                            f"required file must be a normalized package path: {requirement}"
                        )
    overrides = data.get("severity_overrides", {})
    if not isinstance(overrides, dict) or not all(
        isinstance(code, str) and severity in {"error", "warning"}
        for code, severity in overrides.items()
    ):
        raise ValueError("severity_overrides must map finding codes to error or warning")
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {**data, "sha256": hashlib.sha256(canonical).hexdigest()}


def _manifest_value(manifest: dict[str, Any], dotted_path: str) -> Any:
    current: Any = manifest
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def analyze(
    source: Path,
    targets: set[str],
    policy: dict[str, Any] | None = None,
    as_of: str | None = None,
    policy_max_age: int = 90,
) -> dict[str, Any]:
    unknown = targets - TARGETS
    if not targets or unknown:
        raise ValueError(f"targets must be selected from: {', '.join(sorted(TARGETS))}")
    files, source_label = _read_package(source)
    manifest = _manifest(files)
    findings: list[dict[str, Any]] = []
    all_targets = sorted(targets)

    if manifest.get("manifest_version") != 3:
        findings.append(
            _finding(
                "error", "manifest-version", "Manifest V3 is required.", "manifest_version", targets
            )
        )
    for key in ("name", "description", "version"):
        if not isinstance(manifest.get(key), str) or not str(manifest[key]).strip():
            findings.append(
                _finding("error", f"missing-{key}", f"{key} is required.", key, targets)
            )
    if isinstance(manifest.get("version"), str) and not VERSION.fullmatch(manifest["version"]):
        findings.append(
            _finding(
                "error",
                "invalid-version",
                "Version must contain one to four numeric parts.",
                "version",
                targets,
            )
        )

    permissions = manifest.get("permissions", [])
    host_permissions = manifest.get("host_permissions", [])
    if not isinstance(permissions, list) or not all(isinstance(item, str) for item in permissions):
        findings.append(
            _finding(
                "error",
                "permissions-shape",
                "permissions must be a string array.",
                "permissions",
                targets,
            )
        )
        permissions = []
    if not isinstance(host_permissions, list) or not all(
        isinstance(item, str) for item in host_permissions
    ):
        findings.append(
            _finding(
                "error",
                "host-permissions-shape",
                "host_permissions must be a string array.",
                "host_permissions",
                targets,
            )
        )
        host_permissions = []
    for permission in sorted(set(permissions) & HIGH_RISK_PERMISSIONS):
        findings.append(
            _finding(
                "warning",
                "sensitive-permission",
                "A sensitive permission needs a precise user-facing and reviewer justification.",
                permission,
                targets,
            )
        )
    for pattern in sorted(host_permissions):
        if pattern in {"<all_urls>", "http://*/*", "https://*/*", "*://*/*"}:
            findings.append(
                _finding(
                    "warning",
                    "broad-host-access",
                    "Broad host access should be narrowed or explicitly justified.",
                    pattern,
                    targets,
                )
            )

    csp = manifest.get("content_security_policy", {})
    csp_text = json.dumps(csp, sort_keys=True)
    if re.search(r"https?://|unsafe-eval", csp_text, re.IGNORECASE):
        findings.append(
            _finding(
                "error",
                "unsafe-csp",
                "The extension CSP references remote code or unsafe-eval.",
                csp_text,
                targets,
            )
        )
    for name, content in sorted(files.items()):
        if name.casefold().endswith((".js", ".mjs", ".cjs")):
            text = content.decode("utf-8", errors="replace")
            if REMOTE_CODE.search(text):
                findings.append(
                    _finding(
                        "error",
                        "remote-code",
                        "Executable remote-code pattern found.",
                        name,
                        targets,
                    )
                )

    debris = [
        name
        for name in files
        if any(
            part in {".git", "node_modules", "coverage", "tests", "__pycache__"}
            for part in PurePosixPath(name).parts
        )
        or name.casefold().endswith((".map", ".pem", ".key", ".env"))
    ]
    if debris:
        findings.append(
            _finding(
                "warning",
                "package-debris",
                "Development, source-map, or secret-shaped files should be reviewed before submission.",
                ", ".join(debris[:10]),
                targets,
            )
        )
    if manifest.get("update_url") and targets & {"chrome", "edge"}:
        findings.append(
            _finding(
                "warning",
                "store-update-url",
                "Store packages normally should not declare a custom update_url.",
                "update_url",
                targets & {"chrome", "edge"},
            )
        )
    gecko = (
        manifest.get("browser_specific_settings", {}).get("gecko", {})
        if isinstance(manifest.get("browser_specific_settings", {}), dict)
        else {}
    )
    if "firefox" in targets and (
        not isinstance(gecko, dict) or not isinstance(gecko.get("id"), str)
    ):
        findings.append(
            _finding(
                "warning",
                "firefox-id",
                "A stable Gecko extension ID is recommended for predictable signing and updates.",
                "browser_specific_settings.gecko.id",
                {"firefox"},
            )
        )
    icons = manifest.get("icons")
    if not isinstance(icons, dict) or not icons:
        findings.append(
            _finding(
                "warning", "missing-icons", "No extension icons are declared.", "icons", targets
            )
        )
    else:
        for size, name in icons.items():
            if not isinstance(name, str) or name not in files:
                findings.append(
                    _finding(
                        "error",
                        "missing-icon-file",
                        "A declared icon is absent from the package.",
                        f"icons.{size}",
                        targets,
                    )
                )

    if policy:
        policy_targets = targets & set(policy["targets"])
        for target in sorted(policy_targets):
            for field in policy.get("required_manifest_fields", {}).get(target, []):
                value = _manifest_value(manifest, field)
                if value is None or value == "" or value == [] or value == {}:
                    findings.append(
                        _finding(
                            "error",
                            "policy-required-manifest",
                            "The selected policy profile requires this manifest value.",
                            field,
                            {target},
                        )
                    )
            for name in policy.get("required_files", {}).get(target, []):
                if name not in files:
                    findings.append(
                        _finding(
                            "error",
                            "policy-required-file",
                            "The selected policy profile requires this package file.",
                            name,
                            {target},
                        )
                    )
        overrides = policy.get("severity_overrides", {})
        for finding in findings:
            if finding["code"] in overrides:
                finding["severity"] = overrides[finding["code"]]

    findings.sort(key=lambda item: (item["severity"] != "error", item["code"], item["evidence"]))
    counts = {
        level: sum(item["severity"] == level for item in findings) for level in ("error", "warning")
    }
    package_digest = hashlib.sha256(
        b"".join(
            name.encode() + b"\0" + hashlib.sha256(content).digest()
            for name, content in sorted(files.items())
        )
    ).hexdigest()
    return {
        "schema_version": 2,
        "permission_review": permission_review(manifest, files),
        "policy_review": policy_review(
            policy, as_of or datetime.now(timezone.utc).date().isoformat(), policy_max_age
        ),
        "archive_signature": "not-verified; container inspection does not authenticate CRX/XPI signatures",
        "project": PROJECT,
        "source": source_label,
        "targets": all_targets,
        "package_sha256": package_digest,
        "file_count": len(files),
        "manifest": {
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "manifest_version": manifest.get("manifest_version"),
        },
        "summary": {**counts, "ready": counts["error"] == 0},
        "findings": findings,
        "policy_profile": (
            {
                "id": policy["id"],
                "reviewed_at": policy["reviewed_at"],
                "targets": sorted(policy["targets"]),
                "sources": policy.get("sources", []),
                "sha256": policy["sha256"],
            }
            if policy
            else None
        ),
        "boundary": "Static heuristics cannot guarantee marketplace acceptance; recheck current store policies before submission.",
    }


def compare_reports(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    if baseline.get("project") != PROJECT or baseline.get("schema_version") not in {1, 2}:
        raise ValueError("baseline must be an Extension Store Readiness Auditor report")

    def key(finding: dict[str, Any]) -> tuple[str, str, str, tuple[str, ...]]:
        try:
            return (
                str(finding["severity"]),
                str(finding["code"]),
                str(finding["evidence"]),
                tuple(sorted(str(target) for target in finding["targets"])),
            )
        except (KeyError, TypeError) as exc:
            raise ValueError("baseline contains an invalid finding") from exc

    current_by_key = {key(finding): finding for finding in current["findings"]}
    baseline_by_key = {key(finding): finding for finding in baseline.get("findings", [])}
    new_keys = sorted(current_by_key.keys() - baseline_by_key.keys())
    resolved_keys = sorted(baseline_by_key.keys() - current_by_key.keys())
    unchanged_keys = sorted(current_by_key.keys() & baseline_by_key.keys())
    return {
        "new": [current_by_key[item] for item in new_keys],
        "resolved": [baseline_by_key[item] for item in resolved_keys],
        "unchanged": [current_by_key[item] for item in unchanged_keys],
        "summary": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "unchanged": len(unchanged_keys),
        },
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Extension Store Readiness Audit",
        "",
        f"Package: `{report['package_sha256']}`",
        f"Targets: {', '.join(report['targets'])}",
        f"Result: {'Ready for human review' if summary['ready'] else 'Errors require correction'}",
        f"Errors: {summary['error']} | Warnings: {summary['warning']}",
    ]
    if report.get("policy_profile"):
        profile = report["policy_profile"]
        lines.extend(
            [
                f"Policy: `{profile['id']}` reviewed {profile['reviewed_at']} (`{profile['sha256']}`)",
            ]
        )
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("- No static findings.")
    for item in report["findings"]:
        lines.append(
            f"- **{item['severity'].upper()} {item['code']}** — {item['message']} "
            f"Evidence: `{item['evidence']}`. Targets: {', '.join(item['targets'])}."
        )
    if "comparison" in report:
        comparison = report["comparison"]
        lines.extend(
            [
                "",
                "## Baseline Comparison",
                "",
                (
                    f"New: {comparison['summary']['new']} | "
                    f"Resolved: {comparison['summary']['resolved']} | "
                    f"Unchanged: {comparison['summary']['unchanged']}"
                ),
            ]
        )
        for state in ("new", "resolved"):
            for item in comparison[state]:
                lines.append(f"- **{state.title()} {item['code']}** — `{item['evidence']}`")
    lines += [
        "",
        "## Permission and policy review",
        "",
        json.dumps(
            {
                "permissions": report.get("permission_review"),
                "permission_diff": report.get("permission_diff"),
                "policy": report.get("policy_review"),
            },
            indent=2,
        ),
        "",
        "## Boundary",
        "",
        report["boundary"],
        "",
    ]
    return "\n".join(lines)
