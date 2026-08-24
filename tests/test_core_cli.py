import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from extension_store_readiness_auditor.cli import main
from extension_store_readiness_auditor.core import (
    analyze,
    compare_reports,
    load_policy,
    render_json,
    render_markdown,
)


def valid_package(root: Path) -> None:
    (root / "icons").mkdir()
    (root / "icons" / "128.png").write_bytes(b"png")
    (root / "worker.js").write_text("console.log('local');", encoding="utf-8")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "manifest_version": 3,
                "name": "Example",
                "description": "A focused extension.",
                "version": "1.0.0",
                "icons": {"128": "icons/128.png"},
                "background": {"service_worker": "worker.js"},
                "browser_specific_settings": {"gecko": {"id": "example@example.test"}},
            }
        ),
        encoding="utf-8",
    )


def test_clean_directory_is_ready(tmp_path: Path) -> None:
    valid_package(tmp_path)
    report = analyze(tmp_path, {"chrome", "firefox", "edge"})
    assert report["summary"] == {"error": 0, "warning": 0, "ready": True}
    assert "Ready for human review" in render_markdown(report)
    assert '"schema_version": 2' in render_json(report)
    assert report["policy_profile"] is None


def test_risky_package_reports_evidence(tmp_path: Path) -> None:
    valid_package(tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    manifest["permissions"] = ["debugger"]
    manifest["host_permissions"] = ["<all_urls>"]
    manifest["icons"]["16"] = "missing.png"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "worker.js").write_text("eval('x')", encoding="utf-8")
    (tmp_path / "bundle.js.map").write_text("{}", encoding="utf-8")
    report = analyze(tmp_path, {"chrome"})
    codes = {item["code"] for item in report["findings"]}
    assert {
        "sensitive-permission",
        "broad-host-access",
        "remote-code",
        "missing-icon-file",
        "package-debris",
    } <= codes
    assert report["summary"]["ready"] is False


def test_zip_and_root_manifest_validation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    valid_package(source)
    archive_path = tmp_path / "extension.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for path in source.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    assert analyze(archive_path, {"firefox"})["file_count"] == 3
    nested = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("folder/manifest.json", "{}")
    with pytest.raises(ValueError, match="package root"):
        analyze(nested, {"chrome"})


def test_invalid_targets_and_cli_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    valid_package(tmp_path)
    assert main([str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["ready"] is True
    output = tmp_path / "report.md"
    assert main([str(tmp_path), "--output", str(output)]) == 0
    assert main([str(tmp_path), "--output", str(output)]) == 2
    with pytest.raises(ValueError, match="targets"):
        analyze(tmp_path, set())


def test_missing_and_invalid_manifest(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing"):
        analyze(tmp_path, {"edge"})
    (tmp_path / "manifest.json").write_text("[]", encoding="utf-8")
    with pytest.raises(TypeError, match="object"):
        analyze(tmp_path, {"edge"})


def test_manifest_metadata_shapes_and_store_warnings(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "manifest_version": 2,
                "name": "",
                "description": 4,
                "version": "1.beta",
                "permissions": "tabs",
                "host_permissions": [3],
                "content_security_policy": "script-src https://cdn.example 'unsafe-eval'",
                "update_url": "https://updates.example/manifest.xml",
            }
        ),
        encoding="utf-8",
    )
    report = analyze(tmp_path, {"chrome", "firefox", "edge"})
    codes = {item["code"] for item in report["findings"]}
    assert {
        "manifest-version",
        "missing-name",
        "missing-description",
        "invalid-version",
        "permissions-shape",
        "host-permissions-shape",
        "unsafe-csp",
        "store-update-url",
        "firefox-id",
        "missing-icons",
    } <= codes


def test_archive_rejects_unsafe_duplicate_and_invalid_sources(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("../manifest.json", "{}")
    with pytest.raises(ValueError, match="unsafe"):
        analyze(unsafe, {"chrome"})
    duplicate = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("MANIFEST.JSON", "{}")
    with pytest.raises(ValueError, match="duplicate"):
        analyze(duplicate, {"chrome"})
    invalid = tmp_path / "manifest.json"
    invalid.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="directory or ZIP"):
        analyze(invalid, {"chrome"})
    folder = tmp_path / "folder.zip"
    with zipfile.ZipFile(folder, "w") as archive:
        archive.writestr("empty/", b"")
        archive.writestr("manifest.json", b"not-json")
    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        analyze(folder, {"chrome"})


def policy_profile() -> dict[str, object]:
    return {
        "schema_version": 1,
        "id": "reviewed-policy",
        "reviewed_at": "2026-08-06",
        "targets": ["chrome", "firefox"],
        "sources": [
            {
                "title": "Store policy",
                "url": "https://developer.example.test/store-policy",
            }
        ],
        "required_manifest_fields": {
            "chrome": ["minimum_chrome_version"],
            "firefox": ["browser_specific_settings.gecko.id"],
        },
        "required_files": {"chrome": ["store/privacy.md"], "firefox": []},
        "severity_overrides": {"sensitive-permission": "error"},
    }


def test_policy_profile_requirements_overrides_and_fingerprint(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    valid_package(package)
    manifest_path = package / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["permissions"] = ["debugger"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    profile_path = tmp_path / "policy.json"
    profile_path.write_text(json.dumps(policy_profile()), encoding="utf-8")

    policy = load_policy(profile_path)
    report = analyze(package, {"chrome", "firefox"}, policy)
    findings = {(item["code"], item["evidence"]): item for item in report["findings"]}
    assert findings[("sensitive-permission", "debugger")]["severity"] == "error"
    assert ("policy-required-manifest", "minimum_chrome_version") in findings
    assert ("policy-required-file", "store/privacy.md") in findings
    assert report["policy_profile"]["sha256"] == policy["sha256"]
    assert len(policy["sha256"]) == 64
    assert "Policy: `reviewed-policy` reviewed 2026-08-06" in render_markdown(report)


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (lambda profile: profile.update(schema_version=2), "schema version 1"),
        (lambda profile: profile.update(id=""), "requires an id"),
        (lambda profile: profile.update(reviewed_at="August"), "ISO date"),
        (lambda profile: profile.update(targets=["safari"]), "policy targets"),
        (lambda profile: profile.update(sources={}), "sources must be a list"),
        (
            lambda profile: profile["sources"][0].update(url="file:///policy"),
            "HTTP or HTTPS",
        ),
        (
            lambda profile: profile["required_files"].update(chrome=["../private.txt"]),
            "unsafe package member path",
        ),
        (
            lambda profile: profile.update(severity_overrides={"remote-code": "notice"}),
            "severity_overrides",
        ),
    ],
)
def test_invalid_policy_profiles(tmp_path: Path, mutate: Any, error: str) -> None:
    profile = policy_profile()
    mutate(profile)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(profile), encoding="utf-8")
    with pytest.raises((TypeError, ValueError), match=error):
        load_policy(path)


def test_baseline_comparison_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    package = tmp_path / "package"
    package.mkdir()
    valid_package(package)
    baseline = analyze(package, {"chrome"})
    (package / "worker.js").write_text("eval('remote')", encoding="utf-8")
    current = analyze(package, {"chrome"})
    comparison = compare_reports(current, baseline)
    assert comparison["summary"] == {"new": 1, "resolved": 0, "unchanged": 0}
    assert comparison["new"][0]["code"] == "remote-code"
    assert compare_reports(baseline, current)["summary"]["resolved"] == 1

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(render_json(baseline), encoding="utf-8")
    assert main([str(package), "--baseline", str(baseline_path), "--format", "json"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["comparison"]["summary"]["new"] == 1
    output["comparison"] = comparison
    assert "## Baseline Comparison" in render_markdown(output)


def test_rejects_invalid_baselines(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    valid_package(package)
    current = analyze(package, {"chrome"})
    with pytest.raises(ValueError, match="baseline"):
        compare_reports(current, {"project": "other", "schema_version": 2})
    invalid = {**current, "findings": [{"code": "broken"}]}
    with pytest.raises(ValueError, match="invalid finding"):
        compare_reports(current, invalid)
