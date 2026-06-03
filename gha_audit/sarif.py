"""SARIF 2.1.0 serialization for github-actions-audit findings.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub code scanning upload: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github
"""

from __future__ import annotations

import re
from typing import Any

from gha_audit import checks as check_registry
from gha_audit.findings import Finding, Severity

# SARIF 2.1.0 schema URI required by GitHub code scanning
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

ACTOR_VERSION = "0.2.6"
ACTOR_URI = "https://apify.com/unbearable_dev/github-actions-audit"

# Map our severity levels to SARIF level values
# SARIF levels: "error" | "warning" | "note" | "none"
_SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# CVSS-ish security-severity scores used by GitHub code scanning
_SEVERITY_SCORE: dict[str, str] = {
    "critical": "9.0",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.5",
    "info": "1.0",
}

# Reference URL mapping for the tag strings used in Finding.references
_REFERENCE_URLS: dict[str, str] = {
    "GHA-Security-Hardening": (
        "https://docs.github.com/en/actions/security-for-github-actions/"
        "security-guides/security-hardening-for-github-actions"
    ),
    "GHA-Action-Pinning": (
        "https://docs.github.com/en/actions/security-for-github-actions/"
        "security-guides/security-hardening-for-github-actions"
        "#using-third-party-actions"
    ),
    "GHA-Encrypted-Secrets": (
        "https://docs.github.com/en/actions/security-for-github-actions/"
        "security-guides/using-secrets-in-github-actions"
    ),
    "GHA-OIDC": (
        "https://docs.github.com/en/actions/security-for-github-actions/"
        "security-guides/about-security-hardening-with-openid-connect"
    ),
}


def _rule_name(title: str) -> str:
    """Convert a check title to a PascalCase identifier for SARIF rule name."""
    words = re.findall(r"[A-Za-z0-9]+", title)
    return "".join(w.capitalize() for w in words[:6])


def _build_rules() -> list[dict[str, Any]]:
    """Build SARIF tool.driver.rules[] from the full check catalog."""
    rules: list[dict[str, Any]] = []
    for entry in check_registry.catalog():
        rule_id: str = entry["id"]
        severity: str = entry["severity"]
        sarif_level = _SEVERITY_TO_SARIF_LEVEL.get(severity, "note")

        rule: dict[str, Any] = {
            "id": rule_id,
            "name": _rule_name(entry["title"]),
            "shortDescription": {"text": entry["title"]},
            "fullDescription": {"text": entry["title"]},
            "defaultConfiguration": {"level": sarif_level},
            "helpUri": f"{ACTOR_URI}#{rule_id.lower()}",
            "properties": {
                "tags": [entry["category"], "security", "github-actions"],
                "precision": "high",
                "problem.severity": severity,
                "security-severity": _SEVERITY_SCORE.get(severity, "1.0"),
            },
        }
        rules.append(rule)
    return rules


def _build_location(finding: Finding, workflow_path: str) -> dict[str, Any]:
    """Build a SARIF physicalLocation. Uses line_number when present."""
    artifact_location: dict[str, Any] = {
        "uri": workflow_path,
        "uriBaseId": "%SRCROOT%",
    }

    # line_number is defined in Finding but no current check populates it.
    # When present, emit a precise region. When absent (current state),
    # fall back to line 1 — SARIF requires a location; GitHub code scanning
    # accepts file-level annotations at line 1 and displays them as file-level alerts.
    line = finding.line_number if finding.line_number is not None else 1

    physical: dict[str, Any] = {
        "artifactLocation": artifact_location,
        "region": {
            "startLine": line,
            "startColumn": 1,
        },
    }

    location: dict[str, Any] = {"physicalLocation": physical}

    # Logical locations encode job/step context that SARIF viewers can surface
    logical: list[dict[str, Any]] = []
    if finding.job:
        logical.append({"name": finding.job, "kind": "function"})
    if finding.step:
        logical.append({"name": finding.step, "kind": "member"})
    if logical:
        location["logicalLocations"] = logical

    return location


def _finding_to_result(finding: Finding, workflow_path: str) -> dict[str, Any]:
    """Map one Finding to one SARIF result object."""
    level = _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "note")

    # Compose a rich message: title + description + remediation
    parts = [finding.title]
    if finding.description and finding.description != finding.title:
        parts.append(finding.description)
    if finding.remediation:
        parts.append(f"Remediation: {finding.remediation}")
    message_text = "\n\n".join(parts)

    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": level,
        "message": {"text": message_text},
        "locations": [_build_location(finding, workflow_path)],
    }

    # Attach fix snippet as a relatedLocation — SARIF viewers surface these
    # alongside the finding. We cannot emit a real artifactChange without
    # byte-offset knowledge, so we describe it in text.
    if finding.fix_yaml_snippet:
        result["relatedLocations"] = [
            {
                "id": 1,
                "message": {
                    "text": f"Suggested fix:\n{finding.fix_yaml_snippet}"
                },
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": workflow_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1, "startColumn": 1},
                },
            }
        ]

    # Reference URLs in properties
    if finding.references:
        ref_urls = [_REFERENCE_URLS.get(r, r) for r in finding.references]
        result["properties"] = {"references": ref_urls}

    return result


def findings_to_sarif(
    findings: list[Finding],
    workflow_path: str = ".github/workflows/workflow.yml",
    workflow_name: str | None = None,
) -> dict[str, Any]:
    """Serialize a list of Finding objects to a SARIF 2.1.0 document.

    Args:
        findings: The audit findings to serialize.
        workflow_path: Repo-relative path to the workflow file used as the
                       artifact URI (e.g. '.github/workflows/ci.yml').
                       Defaults to a generic placeholder.
        workflow_name: Optional human-readable workflow name for the run description.

    Returns:
        A dict that is a valid SARIF 2.1.0 document, ready for json.dumps().
    """
    rules = _build_rules()
    results = [_finding_to_result(f, workflow_path) for f in findings]

    run_description = f"github-actions-audit scan of {workflow_path}"
    if workflow_name:
        run_description = f"github-actions-audit scan: {workflow_name}"

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "github-actions-audit",
                        "version": ACTOR_VERSION,
                        "informationUri": ACTOR_URI,
                        "organization": "Unbearable Labs",
                        "rules": rules,
                    }
                },
                "results": results,
                "artifacts": [
                    {
                        "location": {
                            "uri": workflow_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "mimeType": "application/x-yaml",
                    }
                ],
                "automationDetails": {
                    "description": {"text": run_description},
                    "id": f"github-actions-audit/{workflow_path}",
                },
                "columnKind": "utf16CodeUnits",
            }
        ],
    }

    return sarif_doc
