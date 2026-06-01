"""Unit tests for permissions checks (GHA-010 to GHA-013) — regression for FP fix."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gha_audit.checks.permissions import (
    CHECKS,
    _ALL_TOKEN_SCOPES,
    _permissions_is_write_all,
    check_write_all,
    check_no_top_level_permissions,
    check_pull_request_target_with_checkout,
)
from gha_audit.parser import resolve_workflow_input


# ── helpers ───────────────────────────────────────────────────────────────────


def run(yaml_str: str) -> list:
    """Parse yaml_str and run all permissions checks, return findings."""
    doc = asyncio.get_event_loop().run_until_complete(
        resolve_workflow_input(yaml_str, None)
    )
    findings = []
    for check in CHECKS:
        findings.extend(check(doc))
    return findings


def ids(findings) -> set[str]:
    return {f.id for f in findings}


# ── unit tests for _permissions_is_write_all helper ──────────────────────────


def test_helper_string_write_all_is_true():
    assert _permissions_is_write_all("write-all") is True


def test_helper_string_read_all_is_false():
    assert _permissions_is_write_all("read-all") is False


def test_helper_empty_dict_is_false():
    assert _permissions_is_write_all({}) is False


def test_helper_none_is_false():
    assert _permissions_is_write_all(None) is False


def test_helper_three_write_scopes_is_false():
    """Release job pattern: contents/attestations/id-token write — NOT write-all."""
    assert _permissions_is_write_all({
        "contents": "write",
        "attestations": "write",
        "id-token": "write",
    }) is False


def test_helper_single_write_scope_is_false():
    assert _permissions_is_write_all({"contents": "write"}) is False


def test_helper_mixed_read_write_is_false():
    assert _permissions_is_write_all({
        "contents": "read",
        "packages": "write",
        "id-token": "write",
    }) is False


def test_helper_all_14_scopes_write_is_true():
    """All 14 known GITHUB_TOKEN scopes set to write IS genuine write-all."""
    perms = {scope: "write" for scope in _ALL_TOKEN_SCOPES}
    assert _permissions_is_write_all(perms) is True


def test_helper_all_14_scopes_plus_extra_write_is_true():
    """More than all known scopes still qualifies (superset)."""
    perms = {scope: "write" for scope in _ALL_TOKEN_SCOPES}
    perms["unknown-future-scope"] = "write"
    assert _permissions_is_write_all(perms) is True


# ── GHA-010 regression: false positive cases that MUST NOT fire ──────────────


def test_gha010_does_not_fire_on_release_job_three_write_scopes():
    """Regression: contents/attestations/id-token write at job level must NOT fire GHA-010."""
    yaml = """
on: push
permissions: read-all
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      attestations: write
      id-token: write
    steps:
      - run: echo release
"""
    findings = run(yaml)
    gha010 = [f for f in findings if f.id == "GHA-010"]
    assert not gha010, f"False positive: GHA-010 fired on least-privilege release job: {gha010}"


def test_gha010_does_not_fire_on_single_write_scope():
    """Single write scope at job level must NOT fire GHA-010."""
    yaml = """
on: push
permissions: read-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo deploy
"""
    assert "GHA-010" not in ids(run(yaml))


def test_gha010_does_not_fire_on_mixed_read_write():
    """docker sign pattern: contents/read + packages/write + id-token/write must NOT fire."""
    yaml = """
on: push
permissions: read-all
jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
    steps:
      - run: echo sign
"""
    assert "GHA-010" not in ids(run(yaml))


# ── GHA-010 true positive cases that MUST fire ───────────────────────────────


def test_gha010_fires_on_string_write_all_at_workflow_level():
    """permissions: write-all at workflow level MUST fire GHA-010."""
    yaml = """
on: push
permissions: write-all
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
    assert "GHA-010" in ids(run(yaml))


def test_gha010_fires_on_string_write_all_at_job_level():
    """permissions: write-all at job level MUST fire GHA-010."""
    yaml = """
on: push
permissions: read-all
jobs:
  j:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
"""
    assert "GHA-010" in ids(run(yaml))


def test_gha010_fires_on_all_14_scopes_write_at_job_level():
    """A dict with all 14 GITHUB_TOKEN scopes set to write IS write-all and MUST fire GHA-010."""
    all_write = "\n".join(
        f"      {scope}: write" for scope in sorted(_ALL_TOKEN_SCOPES)
    )
    yaml = f"""
on: push
permissions: read-all
jobs:
  overkill:
    runs-on: ubuntu-latest
    permissions:
{all_write}
    steps:
      - run: echo hi
"""
    findings = run(yaml)
    gha010 = [f for f in findings if f.id == "GHA-010"]
    assert gha010, f"GHA-010 did not fire when all 14 scopes were set to write"


def test_gha010_fires_on_all_14_scopes_write_at_workflow_level():
    """A dict with all 14 GITHUB_TOKEN scopes at workflow level MUST fire GHA-010."""
    all_write = "\n".join(
        f"  {scope}: write" for scope in sorted(_ALL_TOKEN_SCOPES)
    )
    yaml = f"""
on: push
permissions:
{all_write}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
    assert "GHA-010" in ids(run(yaml))


# ── GHA-011: no top-level permissions ────────────────────────────────────────


def test_gha011_fires_when_no_permissions_anywhere():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
    assert "GHA-011" in ids(run(yaml))


def test_gha011_does_not_fire_when_workflow_level_set():
    yaml = """
on: push
permissions: read-all
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
    assert "GHA-011" not in ids(run(yaml))


def test_gha011_does_not_fire_when_all_jobs_scoped():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo hi
"""
    assert "GHA-011" not in ids(run(yaml))


# ── catalog registration ──────────────────────────────────────────────────────


def test_all_permissions_checks_have_meta():
    """Every check in CHECKS must have __check_meta__ with id/severity/title."""
    missing = [c.__name__ for c in CHECKS if not hasattr(c, "__check_meta__")]
    assert not missing, f"Checks without __check_meta__: {missing}"


def test_permissions_check_ids_in_catalog():
    """GHA-010, GHA-011, GHA-013 must appear in the catalog() output."""
    from gha_audit import checks as registry
    catalog_ids = {e["id"] for e in registry.catalog()}
    expected = {"GHA-010", "GHA-011", "GHA-013"}
    missing = expected - catalog_ids
    assert not missing, f"IDs missing from catalog: {missing}"
