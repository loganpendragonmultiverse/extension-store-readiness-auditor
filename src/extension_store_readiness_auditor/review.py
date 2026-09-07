from __future__ import annotations

import re
from datetime import date
from typing import Any

FIELDS = ("permissions", "optional_permissions", "host_permissions", "optional_host_permissions")
API = re.compile(r"\b(?:chrome|browser)\s*\.\s*([A-Za-z_$][\w$]*)\s*\.")


def permission_review(manifest: dict[str, Any], files: dict[str, bytes]) -> dict[str, Any]:
    declared: dict[str, list[str]] = {}
    unsupported = []
    for field in FIELDS:
        raw = manifest.get(field, [])
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            unsupported.append(field)
            declared[field] = []
        else:
            declared[field] = sorted(set(raw))
    observations: dict[str, list[dict[str, Any]]] = {}
    for name, content in sorted(files.items()):
        if name.lower().endswith((".js", ".mjs", ".cjs")):
            text = content.decode("utf-8", errors="replace")
            for match in API.finditer(text):
                observations.setdefault(match.group(1), []).append(
                    {"file": name, "line": text.count("\n", 0, match.start()) + 1}
                )
    evidence = []
    for permission in sorted(set(declared["permissions"] + declared["optional_permissions"])):
        namespace = permission.split(".")[0]
        evidence.append(
            {
                "permission": permission,
                "status": "namespace-pattern-observed"
                if namespace in observations
                else "no-matching-pattern-observed",
                "locations": observations.get(namespace, []),
            }
        )
    return {
        "declared": declared,
        "unsupported_fields": unsupported,
        "permission_evidence": evidence,
        "observed_namespaces": observations,
        "boundary": "Text patterns may occur in comments/strings and miss aliases, computed properties or generated code. Namespace observation does not prove execution or required permission; no matching pattern does not prove a permission unused. Host-access necessity requires human review.",
    }


def permission_diff(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    old = baseline.get("permission_review", {}).get("declared")
    if not isinstance(old, dict) or any(
        not isinstance(old.get(k), list) or any(not isinstance(v, str) for v in old[k])
        for k in FIELDS
    ):
        return {
            "status": "unavailable",
            "reason": "Baseline predates permission inventory or has unsupported declarations",
        }
    return {
        "status": "compared",
        "fields": {
            k: {
                "added": sorted(set(current["declared"][k]) - set(old[k])),
                "removed": sorted(set(old[k]) - set(current["declared"][k])),
            }
            for k in FIELDS
        },
    }


def policy_review(policy: dict[str, Any] | None, as_of: str, max_age: int = 90) -> dict[str, Any]:
    today = date.fromisoformat(as_of)
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 1:
        raise ValueError("policy maximum age must be a positive integer")
    if policy is None:
        return {
            "status": "not-supplied",
            "as_of": as_of,
            "checklist": [
                "Select an operator-reviewed local policy profile",
                "Verify current official store policy sources before submission",
            ],
        }
    age = (today - date.fromisoformat(policy["reviewed_at"])).days
    sources = [
        {"url": s["url"], "title": s.get("title", s["url"]), "status": "manual-recheck-required"}
        for s in policy.get("sources", [])
    ]
    return {
        "status": "future-review-date"
        if age < 0
        else "stale"
        if age > max_age
        else "within-local-age-window",
        "age_days": age,
        "max_age_days": max_age,
        "as_of": as_of,
        "sources": sources,
        "checklist": [
            "Open each listed official source and review changes",
            "Confirm this profile covers every selected store",
            "Record a new reviewed_at only after an actual review",
        ],
        "boundary": "Age window is an operator heuristic. Sources are not fetched; freshness, source authority and store acceptance are not verified.",
    }
