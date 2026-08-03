from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

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
        for path in sorted(source.rglob("*")):
            if path.is_file():
                relative = path.relative_to(source).as_posix()
                files[relative] = path.read_bytes()
                if len(files) > MAX_FILES:
                    raise ValueError("package exceeds the file-count limit")
        return files, str(source)
    if source.is_file() and source.suffix.casefold() in {".zip", ".xpi", ".crx"}:
        files = {}
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


def analyze(source: Path, targets: set[str]) -> dict[str, Any]:
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
    if "firefox" in targets and not isinstance(gecko.get("id"), str):
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
        "schema_version": 1,
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
        "boundary": "Static heuristics cannot guarantee marketplace acceptance; recheck current store policies before submission.",
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
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("- No static findings.")
    for item in report["findings"]:
        lines.append(
            f"- **{item['severity'].upper()} {item['code']}** — {item['message']} "
            f"Evidence: `{item['evidence']}`. Targets: {', '.join(item['targets'])}."
        )
    lines += ["", "## Boundary", "", report["boundary"], ""]
    return "\n".join(lines)
