import io
import json
import struct
import zipfile

import pytest

from extension_store_readiness_auditor.core import analyze


def package(tmp_path, kind, manifest, members=None):
    files = {
        "manifest.json": json.dumps(
            {
                "manifest_version": 3,
                "name": "Synthetic",
                "description": "Synthetic",
                "version": "1.0",
                **manifest,
            }
        ).encode(),
        **(members or {}),
    }
    if kind == "directory":
        source = tmp_path / "package"
        source.mkdir()
        for name, value in files.items():
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
        return source
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    payload = buffer.getvalue()
    if kind == "crx":
        payload = b"Cr24" + struct.pack("<II", 3, 3) + b"abc" + payload
    source = tmp_path / ("fixture." + kind)
    source.write_bytes(payload)
    return source


@pytest.mark.parametrize("kind", ["directory", "zip", "xpi", "crx"])
@pytest.mark.parametrize(
    "reference",
    [
        "missing.js",
        "../outside.js",
        "/absolute.js",
        "C:/absolute.js",
        "https://example.test/run.js",
        "//example.test/run.js",
        "..%2foutside.js",
        "a\\b.js",
        42,
        None,
        "",
    ],
)
def test_invalid_entrypoints(tmp_path, kind, reference):
    source = package(tmp_path, kind, {"background": {"service_worker": reference}})
    report = analyze(source, {"chrome"})
    findings = [f for f in report["findings"] if f["code"].startswith("entrypoint-")]
    assert len(findings) == 1
    assert findings[0]["evidence"] == "background.service_worker"
    assert findings[0]["severity"] == "error"


@pytest.mark.parametrize("kind", ["directory", "zip", "xpi", "crx"])
def test_all_entrypoints_and_source_preservation(tmp_path, kind):
    manifest = {
        "background": {"service_worker": "worker.js"},
        "content_scripts": [{"js": ["content.js"], "css": ["style.css"]}],
        "action": {"default_popup": "popup.html"},
        "browser_action": {"default_popup": "old.html"},
        "page_action": {"default_popup": "page.html"},
        "options_page": "options.html",
        "options_ui": {"page": "options-ui.html"},
        "devtools_page": "devtools.html",
    }
    names = [
        "worker.js",
        "content.js",
        "style.css",
        "popup.html",
        "old.html",
        "page.html",
        "options.html",
        "options-ui.html",
        "devtools.html",
    ]
    source = package(tmp_path, kind, manifest, {name: b"synthetic" for name in names})
    before = (
        {p: p.read_bytes() for p in source.rglob("*") if p.is_file()}
        if source.is_dir()
        else {source: source.read_bytes()}
    )
    assert not [
        f for f in analyze(source, {"chrome"})["findings"] if f["code"].startswith("entrypoint-")
    ]
    for p, raw in before.items():
        assert p.read_bytes() == raw


@pytest.mark.parametrize(
    "manifest",
    [
        {"background": []},
        {"content_scripts": {}},
        {"content_scripts": [None]},
        {"content_scripts": [{"js": "script.js"}]},
        {"content_scripts": [{"css": [False]}]},
        {"action": "popup.html"},
        {"options_ui": {"page": []}},
        {"devtools_page": 0},
    ],
)
def test_malformed_entrypoint_shapes(tmp_path, manifest):
    source = package(tmp_path, "directory", manifest)
    assert any(
        f["code"].startswith("entrypoint-") for f in analyze(source, {"firefox"})["findings"]
    )


@pytest.mark.parametrize("kind", ["directory", "zip", "xpi", "crx"])
@pytest.mark.parametrize(
    "manifest,location",
    [
        ({"content_scripts": [{"js": ["missing.js"]}]}, "content_scripts.0.js.0"),
        ({"content_scripts": [{"css": ["missing.css"]}]}, "content_scripts.0.css.0"),
        ({"action": {"default_popup": "missing.html"}}, "action.default_popup"),
        ({"browser_action": {"default_popup": "missing.html"}}, "browser_action.default_popup"),
        ({"page_action": {"default_popup": "missing.html"}}, "page_action.default_popup"),
        ({"options_page": "missing.html"}, "options_page"),
        ({"options_ui": {"page": "missing.html"}}, "options_ui.page"),
        ({"devtools_page": "missing.html"}, "devtools_page"),
    ],
)
def test_missing_each_entrypoint(tmp_path, kind, manifest, location):
    source = package(tmp_path, kind, manifest)
    finding = next(
        f for f in analyze(source, {"chrome"})["findings"] if f["code"] == "entrypoint-missing"
    )
    assert finding["evidence"] == location
