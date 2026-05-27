"""Unit tests for supply_chain_advanced checks (GHA-201 to GHA-208)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gha_audit.checks.supply_chain_advanced import (
    CHECKS,
    check_event_injection_run,
    check_mutable_tag_pin,
    check_prt_head_checkout,
    check_retired_tag,
    check_secret_echo_log,
    check_top_level_write_permissions,
    check_unpinned_branch_ref,
    check_untrusted_owner,
)
from gha_audit.parser import resolve_workflow_input


# ── helpers ───────────────────────────────────────────────────────────────────


def run(yaml_str: str) -> list:
    """Parse yaml_str and run all supply_chain_advanced checks, return findings."""
    doc = asyncio.get_event_loop().run_until_complete(
        resolve_workflow_input(yaml_str, None)
    )
    findings = []
    for check in CHECKS:
        findings.extend(check(doc))
    return findings


def ids(findings) -> set[str]:
    return {f.id for f in findings}


# ── GHA-201: unpinned branch ref ──────────────────────────────────────────────


def test_gha201_fires_on_main_branch():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
"""
    assert "GHA-201" in ids(run(yaml))


def test_gha201_fires_on_master_branch():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: third-party/action@master
"""
    assert "GHA-201" in ids(run(yaml))


def test_gha201_does_not_fire_on_sha():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
    assert "GHA-201" not in ids(run(yaml))


def test_gha201_does_not_fire_on_tag():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    # v4 is a tag, not a branch — GHA-201 should not fire, GHA-202 should
    assert "GHA-201" not in ids(run(yaml))


# ── GHA-202: mutable tag pin ──────────────────────────────────────────────────


def test_gha202_fires_on_major_tag():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v41
"""
    assert "GHA-202" in ids(run(yaml))


def test_gha202_fires_on_loose_semver():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4.0.2
"""
    assert "GHA-202" in ids(run(yaml))


def test_gha202_does_not_fire_on_sha():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
    assert "GHA-202" not in ids(run(yaml))


def test_gha202_does_not_fire_on_branch():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
"""
    # Branch covered by GHA-201, not GHA-202
    assert "GHA-202" not in ids(run(yaml))


# ── GHA-203: pull_request_target + head checkout ──────────────────────────────


def test_gha203_fires_on_prt_plus_head_sha():
    yaml = """
on:
  pull_request_target:
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    assert "GHA-203" in ids(run(yaml))


def test_gha203_fires_on_prt_plus_head_ref():
    yaml = """
on:
  pull_request_target:
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.ref }}
"""
    assert "GHA-203" in ids(run(yaml))


def test_gha203_does_not_fire_on_pull_request():
    yaml = """
on:
  pull_request:
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    assert "GHA-203" not in ids(run(yaml))


def test_gha203_does_not_fire_without_head_ref():
    yaml = """
on:
  pull_request_target:
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
    assert "GHA-203" not in ids(run(yaml))


# ── GHA-204: event injection in run: ─────────────────────────────────────────


def test_gha204_fires_on_pr_title_injection():
    yaml = """
on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""
    assert "GHA-204" in ids(run(yaml))


def test_gha204_fires_on_head_commit_message():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.head_commit.message }}"
"""
    assert "GHA-204" in ids(run(yaml))


def test_gha204_does_not_fire_when_passed_via_env():
    yaml = """
on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "$PR_TITLE"
"""
    # env: is safe — only run: literal interpolation triggers
    assert "GHA-204" not in ids(run(yaml))


# ── GHA-205: untrusted owner ──────────────────────────────────────────────────


def test_gha205_fires_on_unknown_owner():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: some-random-org/deploy@abc1234def5678ab9012cdef3456ab7890123456
"""
    assert "GHA-205" in ids(run(yaml))


def test_gha205_does_not_fire_on_trusted_owner():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: step-security/harden-runner@eb238132059eb5670e18e9b5e9f14b76cd0b8a96
      - uses: aquasecurity/trivy-action@c3a14e5b85a09f2f58c73e14c7f30bfab4c5de2b
"""
    assert "GHA-205" not in ids(run(yaml))


# ── GHA-206: top-level write perms without per-job scoping ───────────────────


def test_gha206_fires_on_write_all_no_job_scope():
    yaml = """
on: push
permissions: write-all
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
  k:
    runs-on: ubuntu-latest
    steps:
      - run: echo there
"""
    assert "GHA-206" in ids(run(yaml))


def test_gha206_fires_on_contents_write_no_job_scope():
    yaml = """
on: push
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
    assert "GHA-206" in ids(run(yaml))


def test_gha206_does_not_fire_when_all_jobs_scoped():
    yaml = """
on: push
permissions: write-all
jobs:
  j:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
  k:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - run: echo there
"""
    assert "GHA-206" not in ids(run(yaml))


def test_gha206_does_not_fire_on_read_all():
    yaml = """
on: push
permissions: read-all
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
    assert "GHA-206" not in ids(run(yaml))


# ── GHA-207: secret echo to logs ─────────────────────────────────────────────


def test_gha207_fires_on_echo_secret():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.MY_TOKEN }}"
"""
    assert "GHA-207" in ids(run(yaml))


def test_gha207_fires_on_printf_secret():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: printf "%s" "${{ secrets.MY_TOKEN }}"
"""
    assert "GHA-207" in ids(run(yaml))


def test_gha207_does_not_fire_on_env_var_in_run():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          MY_TOKEN: ${{ secrets.MY_TOKEN }}
        run: echo "$MY_TOKEN"
"""
    assert "GHA-207" not in ids(run(yaml))


# ── GHA-208: retired tag ──────────────────────────────────────────────────────


def test_gha208_fires_on_checkout_v1():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
"""
    assert "GHA-208" in ids(run(yaml))


def test_gha208_fires_on_setup_node_v1():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v1
"""
    assert "GHA-208" in ids(run(yaml))


def test_gha208_does_not_fire_on_checkout_v4():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    assert "GHA-208" not in ids(run(yaml))


def test_gha208_does_not_fire_on_sha():
    yaml = """
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
    assert "GHA-208" not in ids(run(yaml))


# ── fixture-level integration test ───────────────────────────────────────────


def test_bad_fixture_triggers_all_8_checks():
    """The teampcp-class-bad fixture must trigger all 8 new check IDs."""
    fixture = Path(__file__).resolve().parent / "fixtures" / "teampcp-class-bad" / "workflow.yml"
    content = fixture.read_text()
    all_findings = run(content)
    found_ids = ids(all_findings)
    expected = {"GHA-201", "GHA-202", "GHA-203", "GHA-204", "GHA-205", "GHA-206", "GHA-207", "GHA-208"}
    missing = expected - found_ids
    assert not missing, f"Bad fixture missing checks: {missing}. Got: {found_ids}"


def test_good_fixture_passes_all_checks():
    """The teampcp-class-good fixture must produce zero supply_chain_advanced findings."""
    fixture = Path(__file__).resolve().parent / "fixtures" / "teampcp-class-good" / "workflow.yml"
    content = fixture.read_text()
    all_findings = run(content)
    sa_findings = [f for f in all_findings if f.category == "supply_chain_advanced"]
    assert not sa_findings, f"Good fixture triggered: {[f.id for f in sa_findings]}"


# ── catalog registration ──────────────────────────────────────────────────────


def test_all_8_checks_have_meta():
    """Every check in CHECKS must have __check_meta__ with id/severity/title."""
    missing = [c.__name__ for c in CHECKS if not hasattr(c, "__check_meta__")]
    assert not missing, f"Checks without __check_meta__: {missing}"


def test_all_8_check_ids_in_catalog():
    """All 8 new IDs must appear in the catalog() output."""
    from gha_audit import checks as registry
    catalog_ids = {e["id"] for e in registry.catalog()}
    expected = {"GHA-201", "GHA-202", "GHA-203", "GHA-204", "GHA-205", "GHA-206", "GHA-207", "GHA-208"}
    missing = expected - catalog_ids
    assert not missing, f"IDs missing from catalog: {missing}"
