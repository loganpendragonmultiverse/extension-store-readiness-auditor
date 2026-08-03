import json
import zipfile
from pathlib import Path

import pytest

from extension_store_readiness_auditor.cli import main
from extension_store_readiness_auditor.core import analyze, render_json, render_markdown


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
    assert '"schema_version": 1' in render_json(report)


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
