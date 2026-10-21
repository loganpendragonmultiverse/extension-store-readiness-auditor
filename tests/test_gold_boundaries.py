import json
import stat
import zipfile

import pytest

from extension_store_readiness_auditor import core
from extension_store_readiness_auditor.cli import main
from extension_store_readiness_auditor.review import permission_diff


def package(tmp_path, **changes):
    root = tmp_path / "package"
    root.mkdir()
    manifest = {
        "manifest_version": 3,
        "name": "Fixture",
        "description": "Fixture",
        "version": "1.0",
        **changes,
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    return root


def codes(report, code):
    return [x for x in report["findings"] if x["code"] == code]


@pytest.mark.parametrize(
    "version,target,error",
    [
        ("65536", "chrome", True),
        ("65536", "firefox", False),
        ("65535", "edge", False),
        ("0.0", "chrome", True),
        ("0", "firefox", False),
        ("1.01", "firefox", True),
        ("1000000000", "firefox", True),
        ("999999999", "firefox", False),
        ("1.2.3.4.5", "chrome", True),
    ],
)
def test_target_numeric_versions(tmp_path, version, target, error):
    report = core.analyze(package(tmp_path, version=version), {target})
    assert bool(codes(report, "invalid-version")) is error


def test_manifest_version_findings_name_only_affected_stores(tmp_path):
    root = package(tmp_path, manifest_version=2)
    assert not codes(core.analyze(root, {"firefox"}), "manifest-version")
    assert codes(core.analyze(root, {"chrome", "edge", "firefox"}), "manifest-version")[0][
        "targets"
    ] == ["chrome", "edge"]
    for version in [True, 3.0, "3", None]:
        path = root / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["manifest_version"] = version
        path.write_text(json.dumps(manifest))
        assert codes(core.analyze(root, {"firefox"}), "manifest-version")


def test_background_members_optional_shapes_and_potential_risks(tmp_path):
    root = package(
        tmp_path,
        background={"page": "page.html", "scripts": ["script.js"]},
        optional_permissions=["debugger", "<all_urls>"],
        optional_host_permissions=["https://*/*"],
    )
    report = core.analyze(root, {"firefox"})
    assert len(codes(report, "entrypoint-missing")) == 2
    assert (
        codes(report, "sensitive-optional-permission")
        and len(codes(report, "broad-optional-host-access")) == 2
    )
    (root / "page.html").write_text("<p>fixture</p>")
    (root / "script.js").write_text('console.log("fixture")')
    assert not codes(core.analyze(root, {"firefox"}), "entrypoint-missing")
    m = json.loads((root / "manifest.json").read_text())
    m.update(
        optional_permissions=None, optional_host_permissions=[1], background={"scripts": "bad"}
    )
    (root / "manifest.json").write_text(json.dumps(m))
    r = core.analyze(root, {"chrome"})
    assert (
        codes(r, "optional-permissions-shape")
        and codes(r, "optional-host-permissions-shape")
        and codes(r, "entrypoint-shape")
    )


def test_csp_distinguishes_executable_sources_from_images_and_sandbox(tmp_path):
    root = package(
        tmp_path,
        content_security_policy={
            "extension_pages": "script-src 'self'; object-src 'self'; img-src https://images.example",
            "sandbox": "script-src 'unsafe-eval' https://sandbox.example",
        },
    )
    assert not codes(core.analyze(root, {"chrome"}), "unsafe-csp")
    for csp in [
        "script-src https://code.example",
        {"extension_pages": "default-src https://code.example"},
        "script-src 'unsafe-eval'",
    ]:
        m = json.loads((root / "manifest.json").read_text())
        m["content_security_policy"] = csp
        (root / "manifest.json").write_text(json.dumps(m))
        assert codes(core.analyze(root, {"chrome"}), "unsafe-csp")
    m["content_security_policy"] = {"extension_pages": 4}
    (root / "manifest.json").write_text(json.dumps(m))
    assert codes(core.analyze(root, {"chrome"}), "csp-shape")


@pytest.mark.parametrize(
    "name",
    [
        "../bad.js",
        "C:/bad.js",
        "a\\b.js",
        "a//b.js",
        "a/./b.js",
        "a/../b.js",
        "/bad.js",
        "bad\n.js",
    ],
)
def test_archive_rejects_ambiguous_member_names(tmp_path, name):
    p = tmp_path / "fixture.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("manifest.json", "{}")
        member = zipfile.ZipInfo("raw-member")
        member.filename = name  # Preserve exact adversarial bytes on every host OS.
        z.writestr(member, "fixture")
    assert name.encode("utf-8") in p.read_bytes()
    with zipfile.ZipFile(p) as archive:
        assert archive.infolist()[1].orig_filename == name
    with pytest.raises(ValueError, match="unsafe"):
        core.analyze(p, {"chrome"})


def test_archive_symlink_special_and_prefix_collisions(tmp_path):
    for index, mode in enumerate([stat.S_IFLNK, stat.S_IFIFO]):
        p = tmp_path / (str(index) + ".zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("manifest.json", "{}")
            i = zipfile.ZipInfo("link.js")
            i.create_system = 3
            i.external_attr = (mode | 0o600) << 16
            z.writestr(i, "fixture")
        with pytest.raises(ValueError, match="symlinks and special"):
            core.analyze(p, {"chrome"})
    for index, names in enumerate([["a", "a/b"], ["A/a", "a/b"]]):
        p = tmp_path / ("collision" + str(index) + ".zip")
        with zipfile.ZipFile(p, "w") as z:
            for name in names:
                z.writestr(name, "fixture")
        with pytest.raises(ValueError, match="conflicting"):
            core.analyze(p, {"chrome"})


def test_root_symlink_and_manifest_name_boundary(tmp_path):
    root = package(tmp_path)
    try:
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symlink"):
        core.analyze(alias, {"chrome"})
    (root / "manifest.json").rename(root / "MANIFEST.JSON")
    with pytest.raises(ValueError, match="lowercase"):
        core.analyze(root, {"chrome"})


def test_incomplete_and_ambiguous_baselines_never_claim_resolution(tmp_path):
    current = core.analyze(package(tmp_path), {"chrome"})
    for bad in [
        {k: v for k, v in current.items() if k != "findings"},
        {**current, "findings": [current["findings"][0]] * 2},
        {
            **current,
            "findings": [
                {"severity": "notice", "code": "x", "evidence": "x", "targets": ["chrome"]}
            ],
        },
    ]:
        with pytest.raises((ValueError, TypeError)):
            core.compare_reports(current, bad)
    assert (
        permission_diff(current["permission_review"], {**current, "permission_review": []})[
            "status"
        ]
        == "unavailable"
    )


def test_strict_manifest_and_cli_destination_race(tmp_path, monkeypatch):
    root = package(tmp_path)
    manifest = root / "manifest.json"
    original = manifest.read_bytes()
    dest = tmp_path / "result.json"
    real = core.analyze
    from extension_store_readiness_auditor import cli

    def raced(*args, **kwargs):
        report = real(*args, **kwargs)
        dest.write_text("racer")
        return report

    monkeypatch.setattr(cli, "analyze", raced)
    assert (
        main([str(root), "--output", str(dest)]) == 2
        and dest.read_text() == "racer"
        and manifest.read_bytes() == original
    )
    manifest.write_text('{"manifest_version":3,"manifest_version":2}')
    assert main([str(root)]) == 2


def test_policy_fingerprint_and_exact_schema_and_dates(tmp_path):
    policy = {
        "schema_version": 1,
        "id": "fixture",
        "reviewed_at": "2026-10-21",
        "targets": ["chrome"],
    }
    p = tmp_path / "policy.json"
    for mutation in [
        {"schema_version": True},
        {"reviewed_at": "20261021"},
        {"targets": ["chrome", "chrome"]},
        {"required_manifest_fields": {"chrome": ["a..b"]}},
        {"severity_overrides": {"code": []}},
    ]:
        p.write_text(json.dumps({**policy, **mutation}))
        with pytest.raises((ValueError, TypeError)):
            core.load_policy(p)
    p.write_text(json.dumps(policy))
    loaded = core.load_policy(p)
    loaded["id"] = "changed"
    with pytest.raises(ValueError, match="fingerprint"):
        core.analyze(package(tmp_path), {"chrome"}, loaded)


def test_changed_target_scope_is_explicit_and_never_false_resolution(tmp_path):
    root = package(tmp_path, permissions=["debugger"])
    chrome = core.analyze(root, {"chrome"})
    firefox = core.analyze(root, {"firefox"})
    unavailable = core.compare_reports(firefox, chrome)
    assert unavailable["status"] == "unavailable-target-scope"
    assert unavailable["summary"] == {"new": 0, "resolved": 0, "unchanged": 0}
    assert unavailable["not_rechecked"] and unavailable["not_compared"]
    broader = core.analyze(root, {"chrome", "firefox"})
    compared = core.compare_reports(broader, chrome)
    assert compared["shared_targets"] == ["chrome"] and compared["current_only_targets"] == [
        "firefox"
    ]
    assert compared["summary"]["resolved"] == 0 and compared["summary"]["new"] == 0


def test_unsupported_permission_shapes_cannot_imply_added_or_removed_permissions():
    from extension_store_readiness_auditor.review import permission_review

    valid = permission_review({"permissions": ["storage"]}, {})
    invalid = permission_review({"permissions": "storage"}, {})
    assert permission_diff(invalid, {"permission_review": valid})["status"] == "unavailable"
    assert permission_diff(valid, {"permission_review": invalid})["status"] == "unavailable"


@pytest.mark.parametrize("manifest_version", [2, 3])
def test_repeated_declarations_round_trip_own_baseline(tmp_path, manifest_version):
    root = package(
        tmp_path,
        manifest_version=manifest_version,
        permissions=["<all_urls>", "<all_urls>", "debugger", "debugger"],
        host_permissions=["<all_urls>", "<all_urls>"],
        optional_permissions=["tabs", "tabs"],
        optional_host_permissions=["<all_urls>", "<all_urls>"],
    )
    policy = {
        "schema_version": 1,
        "id": "fixture",
        "reviewed_at": "2026-10-21",
        "targets": ["firefox"],
        "required_manifest_fields": {"firefox": ["missing.field", "missing.field"]},
        "required_files": {"firefox": ["missing.js", "missing.js"]},
    }
    report = core.analyze(root, {"firefox"}, policy, as_of="2026-10-21")
    identities = [
        (v["severity"], v["code"], v["evidence"], tuple(v["targets"])) for v in report["findings"]
    ]
    assert len(identities) == len(set(identities))
    comparison = core.compare_reports(report, report)
    assert comparison["summary"] == {"new": 0, "resolved": 0, "unchanged": len(identities)}
    assert report["summary"]["error"] == sum(v["severity"] == "error" for v in report["findings"])
    assert len(codes(report, "policy-required-file")) == 1
    with pytest.raises(ValueError, match="duplicate"):
        core.compare_reports(report, {**report, "findings": report["findings"] * 2})


def test_namespace_line_evidence_scans_each_text_interval_once():
    from extension_store_readiness_auditor.review import permission_review

    text = "chrome.tabs.query();browser.tabs.get();\n\n  browser.storage.local.get();\nchrome.tabs.get();"
    report = permission_review({"permissions": ["tabs", "storage"]}, {"fixture.js": text.encode()})
    assert report["observed_namespaces"] == {
        "tabs": [
            {"file": "fixture.js", "line": 1},
            {"file": "fixture.js", "line": 1},
            {"file": "fixture.js", "line": 4},
        ],
        "storage": [{"file": "fixture.js", "line": 3}],
    }
    large = permission_review({}, {"many.js": ("chrome.tabs.query();\n" * 20000).encode()})
    observations = large["observed_namespaces"]["tabs"]
    assert len(observations) == 20000
    assert [v["line"] for v in observations] == list(range(1, 20001))
