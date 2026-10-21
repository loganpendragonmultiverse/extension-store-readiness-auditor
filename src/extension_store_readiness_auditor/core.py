from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import zipfile
from collections.abc import Iterable
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from ._archive import read_member
from ._io import (
    checked_path,
    code_span,
    json_fence,
    load_json,
    parse_json,
    read_bytes,
    validate_json,
)
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
VERSION = re.compile(r"^(0|[1-9][0-9]{0,8})(?:\.(0|[1-9][0-9]{0,8})){0,3}$")
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
    if (
        not name
        or any(part in {"", ".", ".."} for part in name.split("/"))
        or any(c in name for c in ("\\", ":"))
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
    ):
        raise ValueError(f"unsafe package member path: {name}")
    return name


def _read_package(source: Path) -> tuple[dict[str, bytes], str]:
    source = checked_path(source).resolve()
    names: dict[str, tuple[str, str]] = {}

    def register(name: str, kind: str = "file") -> str:
        name = _safe_name(name)
        parts = name.split("/")
        for index in range(len(parts)):
            prefix = "/".join(parts[: index + 1])
            node_kind = kind if index == len(parts) - 1 else "directory"
            old = names.get(prefix.casefold())
            if old and (old[0] != prefix or old[1] != node_kind or node_kind == "file"):
                raise ValueError(f"duplicate or conflicting package member path: {name}")
            names[prefix.casefold()] = (prefix, node_kind)
        return name

    if source.is_dir():
        files: dict[str, bytes] = {}
        total = 0
        entries = 0

        def walk_error(error: OSError) -> None:
            raise error

        for directory, dirs, leaves in os.walk(source, followlinks=False, onerror=walk_error):
            entries += len(dirs) + len(leaves)
            if entries > MAX_FILES:
                raise ValueError("package exceeds the file-count limit")
            for name in sorted(dirs + leaves):
                path = Path(directory) / name
                if path.is_symlink():
                    raise ValueError("package symlinks are unsupported")
                if name in dirs:
                    continue
                relative = register(path.relative_to(source).as_posix())
                if path.stat().st_size > MAX_UNCOMPRESSED - total:
                    raise ValueError("package exceeds the uncompressed-size limit")
                raw = read_bytes(path, MAX_UNCOMPRESSED - total)
                total += len(raw)
                files[relative] = raw
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
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise ValueError("package symlinks and special files are unsupported")
                if info.flag_bits & 1:
                    raise ValueError("encrypted package members are unsupported")
                # ZipInfo.filename normalizes platform separators on Windows;
                # orig_filename preserves the actual archive spelling to validate.
                raw_name = info.orig_filename
                is_directory = info.is_dir()
                name = register(
                    raw_name.rstrip("/") if is_directory else raw_name,
                    "directory" if is_directory else "file",
                )
                limit = 0 if is_directory else info.file_size
                try:
                    raw = read_member(archive, info, limit, MAX_UNCOMPRESSED)
                except (RuntimeError, NotImplementedError) as exc:
                    raise ValueError(
                        "package member encryption/compression is unsupported"
                    ) from exc
                if not is_directory:
                    files[name] = raw
        return files, str(source)
    raise ValueError("source must be an extension directory or ZIP, XPI, or CRX archive")


def _manifest(files: dict[str, bytes]) -> dict[str, Any]:
    candidates = [name for name in files if name.casefold() == "manifest.json"]
    if not candidates:
        nested = [name for name in files if PurePosixPath(name).name.casefold() == "manifest.json"]
        if nested:
            raise ValueError("manifest.json must be at the package root")
        raise ValueError("manifest.json is missing")
    if candidates != ["manifest.json"]:
        raise ValueError("manifest.json must use its exact lowercase package name")
    try:
        data = parse_json(files[candidates[0]])
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"manifest.json is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TypeError("manifest.json must contain an object")
    return data


def load_policy(path: Path) -> dict[str, Any]:
    return _validate_policy(load_json(path))


def _validate_policy(profile: Any) -> dict[str, Any]:
    validate_json(profile)
    if not isinstance(profile, dict):
        raise TypeError("policy profile must be a schema version 1 object")
    data = {key: item for key, item in profile.items() if key != "sha256"}
    if type(data.get("schema_version")) is not int or data.get("schema_version") != 1:
        raise ValueError("policy profile must be a schema version 1 object")
    profile_id = data.get("id")
    if not isinstance(profile_id, str) or not profile_id.strip():
        raise ValueError("policy profile requires an id")
    reviewed_at = data.get("reviewed_at")
    if not isinstance(reviewed_at, str):
        raise TypeError("policy profile requires a reviewed_at date")
    try:
        if date.fromisoformat(reviewed_at).isoformat() != reviewed_at:
            raise ValueError("noncanonical date")
    except ValueError as exc:
        raise ValueError("policy profile reviewed_at must be an ISO date") from exc
    targets = data.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or not all(isinstance(target, str) for target in targets)
        or not set(targets) <= TARGETS
        or len(set(targets)) != len(targets)
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
            if key == "required_manifest_fields" and any(
                any(not part for part in requirement.split(".")) for requirement in requirements
            ):
                raise ValueError("manifest policy paths must use nonempty dotted components")
            if key == "required_files":
                for requirement in requirements:
                    if _safe_name(requirement) != requirement.replace("\\", "/"):
                        raise ValueError(
                            f"required file must be a normalized package path: {requirement}"
                        )
    overrides = data.get("severity_overrides", {})
    if not isinstance(overrides, dict) or not all(
        isinstance(code, str)
        and bool(code)
        and isinstance(severity, str)
        and severity in {"error", "warning"}
        for code, severity in overrides.items()
    ):
        raise ValueError("severity_overrides must map finding codes to error or warning")
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    if "sha256" in profile and profile["sha256"] != digest:
        raise ValueError("policy fingerprint differs from its content")
    return {**data, "sha256": digest}


def _manifest_value(manifest: dict[str, Any], dotted_path: str) -> Any:
    current: Any = manifest
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _entrypoint_findings(
    manifest: dict[str, Any], files: dict[str, bytes], targets: set[str]
) -> list[dict[str, Any]]:
    """Check only literal package members; never resolve or execute references."""
    findings: list[dict[str, Any]] = []

    def error(code: str, location: str, message: str) -> None:
        findings.append(_finding("error", code, message, location, targets))

    def reference(value: Any, location: str) -> None:
        if not isinstance(value, str) or not value:
            error("entrypoint-shape", location, "Entrypoint must be a nonempty local package path.")
            return
        parts = value.split("/")
        if (
            any(part in {"", ".", ".."} for part in parts)
            or any(character in value for character in ("\\", ":", "?", "#", "%"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            error(
                "entrypoint-path",
                location,
                "Entrypoint must be an unambiguous relative package path without URL syntax.",
            )
        elif value not in files:
            error("entrypoint-missing", location, "Declared entrypoint is absent from the package.")

    for parent, key in (
        ("background", "service_worker"),
        ("action", "default_popup"),
        ("browser_action", "default_popup"),
        ("page_action", "default_popup"),
        ("options_ui", "page"),
    ):
        if parent not in manifest:
            continue
        value = manifest[parent]
        if not isinstance(value, dict):
            error("entrypoint-shape", parent, "Entrypoint container must be an object.")
        elif key in value:
            # Chromium treats an empty popup as no popup, not a file reference.
            if key == "default_popup" and value[key] == "":
                continue
            reference(value[key], f"{parent}.{key}")
    background = manifest.get("background")
    if isinstance(background, dict):
        if "page" in background:
            reference(background["page"], "background.page")
        if "scripts" in background:
            if not isinstance(background["scripts"], list):
                error(
                    "entrypoint-shape", "background.scripts", "Background scripts must be an array."
                )
            else:
                for index, value in enumerate(background["scripts"]):
                    reference(value, f"background.scripts.{index}")
    for key in ("options_page", "devtools_page"):
        if key in manifest:
            reference(manifest[key], key)
    if "content_scripts" in manifest:
        scripts = manifest["content_scripts"]
        if not isinstance(scripts, list):
            error("entrypoint-shape", "content_scripts", "Content scripts must be an array.")
        else:
            for index, script in enumerate(scripts):
                location = f"content_scripts.{index}"
                if not isinstance(script, dict):
                    error("entrypoint-shape", location, "Content script must be an object.")
                    continue
                for key in ("js", "css"):
                    if key not in script:
                        continue
                    values = script[key]
                    if not isinstance(values, list):
                        error(
                            "entrypoint-shape", f"{location}.{key}", "Entrypoints must be an array."
                        )
                        continue
                    for item, value in enumerate(values):
                        reference(value, f"{location}.{key}.{item}")
    return findings


def analyze(
    source: Path,
    targets: set[str],
    policy: dict[str, Any] | None = None,
    as_of: str | None = None,
    policy_max_age: int = 90,
) -> dict[str, Any]:
    if not isinstance(targets, set) or any(not isinstance(t, str) for t in targets):
        raise ValueError("targets must be a set of known store names")
    if policy is not None:
        policy = _validate_policy(policy)
    unknown = targets - TARGETS
    if not targets or unknown:
        raise ValueError(f"targets must be selected from: {', '.join(sorted(TARGETS))}")
    files, source_label = _read_package(source)
    manifest = _manifest(files)
    findings: list[dict[str, Any]] = []
    findings.extend(_entrypoint_findings(manifest, files, targets))
    all_targets = sorted(targets)

    manifest_version = manifest.get("manifest_version")
    unsupported = {
        target
        for target in targets
        if type(manifest_version) is not int
        or manifest_version not in ({2, 3} if target == "firefox" else {3})
    }
    if unsupported:
        findings.append(
            _finding(
                "error",
                "manifest-version",
                "Selected targets require Manifest V3 for new Chromium-store submissions; Firefox accepts V2 or V3.",
                "manifest_version",
                unsupported,
            )
        )
    for key in ("name", "description", "version"):
        if not isinstance(manifest.get(key), str) or not str(manifest[key]).strip():
            findings.append(
                _finding("error", f"missing-{key}", f"{key} is required.", key, targets)
            )
    version = manifest.get("version")
    if isinstance(version, str):
        invalid = set(targets) if not VERSION.fullmatch(version) else set()
        if not invalid:
            parts = [int(part) for part in version.split(".")]
            if max(parts) > 65535 or not any(parts):
                invalid = targets & {"chrome", "edge"}
        if invalid:
            findings.append(
                _finding(
                    "error",
                    "invalid-version",
                    "Version must match the selected target's bounded numeric version format.",
                    "version",
                    invalid,
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

    for field, code in (
        ("optional_permissions", "optional-permissions-shape"),
        ("optional_host_permissions", "optional-host-permissions-shape"),
    ):
        raw = manifest.get(field, [])
        if not isinstance(raw, list) or any(not isinstance(v, str) for v in raw):
            findings.append(
                _finding(
                    "error", code, "Optional declarations must be string arrays.", field, targets
                )
            )
            continue
        for value in sorted(set(raw)):
            if field == "optional_permissions" and value in HIGH_RISK_PERMISSIONS:
                findings.append(
                    _finding(
                        "warning",
                        "sensitive-optional-permission",
                        "A potentially requested sensitive permission needs human justification.",
                        value,
                        targets,
                    )
                )
            if value in {"<all_urls>", "http://*/*", "https://*/*", "*://*/*"}:
                findings.append(
                    _finding(
                        "warning",
                        "broad-optional-host-access",
                        "Potential broad host access needs human review.",
                        value,
                        targets,
                    )
                )
    if manifest_version == 2:
        for value in sorted(set(permissions)):
            if value in {"<all_urls>", "http://*/*", "https://*/*", "*://*/*"}:
                findings.append(
                    _finding(
                        "warning",
                        "broad-host-access",
                        "Broad host access needs human review.",
                        value,
                        targets,
                    )
                )

    csp = manifest.get("content_security_policy", {})
    if isinstance(csp, dict):
        page_csp = csp.get("extension_pages", "")
        malformed_csp = any(not isinstance(v, str) for v in csp.values())
    else:
        page_csp = csp
        malformed_csp = not isinstance(csp, str)
    if malformed_csp:
        findings.append(
            _finding(
                "error",
                "csp-shape",
                "CSP declarations must contain strings.",
                "content_security_policy",
                targets,
            )
        )
    elif isinstance(page_csp, str):
        directives: dict[str, list[str]] = {}
        for directive in page_csp.split(";"):
            tokens = directive.lower().split()
            if tokens:
                directives.setdefault(tokens[0], tokens[1:])
        # Only executable extension-page directives are inspected. Remote images,
        # connections and the separate sandbox policy are not executable evidence.
        sources = []
        for name in (
            "script-src",
            "script-src-elem",
            "script-src-attr",
            "worker-src",
            "object-src",
        ):
            sources.extend(directives.get(name, directives.get("default-src", [])))
        if any(re.search(r"https?://|^https?:$|unsafe-eval", token) for token in sources):
            findings.append(
                _finding(
                    "error",
                    "unsafe-csp",
                    "An extension-page executable CSP directive permits remote code or unsafe-eval.",
                    page_csp,
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

    # A finding identity is stable even when declarations or policy requirements repeat.
    unique: dict[tuple[str, str, str, tuple[str, ...]], dict[str, Any]] = {}
    for item in findings:
        identity = (item["severity"], item["code"], item["evidence"], tuple(item["targets"]))
        unique.setdefault(identity, item)
    findings = list(unique.values())
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
        "builtin_policy_snapshot": {
            "reviewed_at": "2026-10-21",
            "scope": "New submissions; conservative static checks, not store approval",
            "sources": [
                "https://developer.chrome.com/docs/extensions/reference/manifest/version",
                "https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline",
                "https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/version",
                "https://blog.mozilla.org/en/firefox/firefox-manifest-v3-adblockers/",
                "https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/manifest-v3",
            ],
        },
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
    if (
        not isinstance(baseline, dict)
        or baseline.get("project") != PROJECT
        or type(baseline.get("schema_version")) is not int
        or baseline.get("schema_version") not in {1, 2}
    ):
        raise ValueError("baseline must be an Extension Store Readiness Auditor report")
    targets = baseline.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or any(not isinstance(t, str) for t in targets)
        or not set(targets) <= TARGETS
        or len(set(targets)) != len(targets)
    ):
        raise ValueError("baseline targets must name its audit scope")
    if not isinstance(baseline.get("findings"), list):
        raise TypeError("baseline requires an explicit findings array")
    shared = set(current["targets"]) & set(targets)

    def key(
        finding: dict[str, Any], allowed: set[str], scope: set[str]
    ) -> tuple[str, str, str, tuple[str, ...]]:
        if (
            not isinstance(finding, dict)
            or finding.get("severity") not in ("error", "warning")
            or not isinstance(finding.get("code"), str)
            or not finding["code"]
            or not isinstance(finding.get("evidence"), str)
            or not isinstance(finding.get("targets"), list)
            or not finding["targets"]
            or any(not isinstance(t, str) for t in finding["targets"])
            or not set(finding["targets"]) <= allowed
            or len(set(finding["targets"])) != len(finding["targets"])
        ):
            raise ValueError("baseline contains an invalid finding")
        return (
            finding["severity"],
            finding["code"],
            finding["evidence"],
            tuple(sorted(set(finding["targets"]) & scope)),
        )

    keys = [key(f, set(targets), set(targets)) for f in baseline["findings"]]
    if len(keys) != len(set(keys)):
        raise ValueError("baseline contains duplicate finding identities")
    current_by_key = {
        key(f, set(current["targets"]), shared): f
        for f in current["findings"]
        if set(f["targets"]) & shared
    }
    baseline_by_key = {
        key(f, set(targets), shared): f for f in baseline["findings"] if set(f["targets"]) & shared
    }
    comparable_baseline = sum(bool(set(f["targets"]) & shared) for f in baseline["findings"])
    if len(baseline_by_key) != comparable_baseline:
        raise ValueError("baseline has ambiguous identities within the shared target scope")
    new_keys = sorted(current_by_key.keys() - baseline_by_key.keys())
    resolved_keys = sorted(baseline_by_key.keys() - current_by_key.keys())
    unchanged_keys = sorted(current_by_key.keys() & baseline_by_key.keys())
    return {
        "status": "compared" if shared else "unavailable-target-scope",
        "shared_targets": sorted(shared),
        "current_only_targets": sorted(set(current["targets"]) - set(targets)),
        "baseline_only_targets": sorted(set(targets) - set(current["targets"])),
        "not_rechecked": [f for f in baseline["findings"] if not set(f["targets"]) & shared],
        "not_compared": [f for f in current["findings"] if not set(f["targets"]) & shared],
        "boundary": "Finding states apply only to shared store targets. Findings outside the shared scope are not classified as new or resolved.",
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
    return json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


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
                f"Policy: {code_span(profile['id'])} reviewed {profile['reviewed_at']} (`{profile['sha256']}`)",
            ]
        )
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("- No static findings.")
    for item in report["findings"]:
        lines.append(
            f"- **{item['severity'].upper()} {item['code']}** — {item['message']} "
            f"Evidence: {code_span(item['evidence'])}. Targets: {', '.join(item['targets'])}."
        )
    if "comparison" in report:
        comparison = report["comparison"]
        lines.extend(
            [
                "",
                "## Baseline Comparison",
                "",
                f"Shared targets: {', '.join(comparison['shared_targets']) or 'none; comparison unavailable'}",
                comparison["boundary"],
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
                lines.append(
                    f"- **{state.title()}** {code_span(item['code'])} — {code_span(item['evidence'])}"
                )
    lines += [
        "",
        "## Permission and policy review",
        "",
        json_fence(
            json.dumps(
                {
                    "permissions": report.get("permission_review"),
                    "permission_diff": report.get("permission_diff"),
                    "policy": report.get("policy_review"),
                },
                indent=2,
            )
        ),
        "",
        "## Boundary",
        "",
        report["boundary"],
        "",
    ]
    return "\n".join(lines)
