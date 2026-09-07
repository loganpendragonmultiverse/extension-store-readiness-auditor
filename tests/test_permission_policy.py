import io
import json
import struct
import zipfile

import pytest

from extension_store_readiness_auditor import core
from extension_store_readiness_auditor.cli import main
from extension_store_readiness_auditor.core import analyze
from extension_store_readiness_auditor.review import (
    permission_diff,
    permission_review,
    policy_review,
)


def package_bytes():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Fixture",
                    "description": "Fixture",
                    "version": "1.0",
                    "permissions": ["storage", "history"],
                    "optional_permissions": ["tabs"],
                    "host_permissions": ["https://example.test/*"],
                }
            ),
        )
        archive.writestr(
            "worker.js",
            'chrome.storage.local.get("key");\n// browser.history.search is only a comment',
        )
    return buffer.getvalue()


@pytest.mark.parametrize("kind", ["xpi", "crx2", "crx3"])
def test_container_fixtures_and_permission_evidence(tmp_path, kind):
    payload = package_bytes()
    if kind == "crx2":
        payload = b"Cr24" + struct.pack("<III", 2, 3, 3) + b"keySIG" + payload
    if kind == "crx3":
        payload = b"Cr24" + struct.pack("<II", 3, 3) + b"abc" + payload
    source = tmp_path / ("fixture.xpi" if kind == "xpi" else "fixture.crx")
    source.write_bytes(payload)
    report = analyze(source, {"chrome"}, as_of="2026-09-07")
    assert report["permission_review"]["declared"]["permissions"] == ["history", "storage"]
    assert report["permission_review"]["observed_namespaces"]["history"][0]["line"] == 2
    assert "not-verified" in report["archive_signature"]
    assert source.read_bytes() == payload
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(report))
    assert (
        main(
            [
                str(source),
                "--target",
                "chrome",
                "--baseline",
                str(baseline),
                "--as-of",
                "2026-09-07",
            ]
        )
        == 0
    )


@pytest.mark.parametrize(
    "header",
    [
        b"bad",
        b"Cr24" + struct.pack("<II", 9, 0),
        b"Cr24" + struct.pack("<II", 3, 999999999),
        b"Cr24" + struct.pack("<II", 3, 1) + b"aWRONG",
    ],
)
def test_bad_crx_headers(tmp_path, header):
    source = tmp_path / "bad.crx"
    source.write_bytes(header)
    with pytest.raises(ValueError):
        analyze(source, {"chrome"})


def test_permission_diff_and_uncertainty():
    old = permission_review({"permissions": ["storage"], "optional_permissions": ["tabs"]}, {})
    new = permission_review(
        {
            "permissions": ["history"],
            "optional_permissions": ["storage"],
            "host_permissions": ["https://example.test/*"],
        },
        {"a.js": b"chrome.history.search({});"},
    )
    changes = permission_diff(new, {"permission_review": old})
    assert changes["fields"]["permissions"] == {"added": ["history"], "removed": ["storage"]}
    assert changes["fields"]["optional_permissions"]["removed"] == ["tabs"]
    assert permission_diff(new, {})["status"] == "unavailable"
    bad = permission_review({"optional_permissions": None}, {})
    assert bad["unsupported_fields"] == ["optional_permissions"]
    assert "does not prove" in new["boundary"]


def test_policy_age_sources_and_limits():
    policy = {
        "reviewed_at": "2026-01-01",
        "sources": [
            {
                "url": "https://developer.chrome.com/docs/webstore/program-policies/",
                "title": "Official policy",
            }
        ],
    }
    result = policy_review(policy, "2026-09-07")
    assert (
        result["status"] == "stale" and result["sources"][0]["status"] == "manual-recheck-required"
    )
    assert policy_review(policy, "2025-01-01")["status"] == "future-review-date"
    assert policy_review(policy, "2026-01-02")["status"] == "within-local-age-window"
    with pytest.raises(ValueError):
        policy_review(policy, "2026-01-02", 0)
    assert policy_review(None, "2026-01-02")["status"] == "not-supplied"


def test_unpacked_size_bound(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    (package / "huge").write_bytes(b"1234")
    monkeypatch.setattr(core, "MAX_UNCOMPRESSED", 3)
    with pytest.raises(ValueError, match="size"):
        analyze(package, {"chrome"})
