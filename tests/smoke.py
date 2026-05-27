"""Smoke test for github-actions-audit — direct call, bypassing Apify Standby + MCP transport."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gha_audit import checks as registry
from gha_audit.findings import summarize
from gha_audit.parser import resolve_workflow_input


async def audit_file(label: str, path: Path):
    content = path.read_text()
    print(f"\n{'=' * 70}")
    print(f"FIXTURE: {label} ({path.name}, {len(content)} bytes)")
    print(f"{'=' * 70}")

    doc = await resolve_workflow_input(content, None)
    print(f"Parsed: name={doc.name}, jobs={list(doc.jobs.keys())}, triggers={doc.on}")

    findings = registry.run_all(doc)
    summary = summarize(findings)
    print(f"\nSUMMARY: {summary['total_findings']} findings")
    print(f"  by severity: {summary['by_severity']}")
    print(f"  by category: {summary['by_category']}")
    print()

    from gha_audit.findings import SEVERITY_RANK
    for f in sorted(findings, key=lambda x: (
        -SEVERITY_RANK.get(x.severity, 0),
        x.id,
        x.job or "",
    )):
        loc = f"{f.job}" + (f"/{f.step}" if f.step else "")
        print(f"  [{f.severity.upper():6}] {f.id}: {f.title} ({loc})")

    return findings


async def main():
    fixtures_dir = Path(__file__).resolve().parent

    bad_findings = await audit_file("BAD (should fire many checks)", fixtures_dir / "bad-workflow.yml")
    good_findings = await audit_file("GOOD (clean workflow)", fixtures_dir / "good-workflow.yml")

    print("\n" + "=" * 70)
    print("EXPECTED FINDINGS ON BAD FIXTURE")
    print("=" * 70)
    expected_ids = [
        "GHA-001",  # secret in run
        "GHA-002",  # echo of secret
        "GHA-003",  # secret in if:
        "GHA-004",  # hardcoded API_TOKEN env
        "GHA-010",  # write-all at job
        "GHA-011",  # workflow-level no perms (unscoped_job triggers it)
        "GHA-013",  # pull_request_target + PR head checkout
        "GHA-020",  # tj-actions/changed-files@v3 (tag)
        "GHA-021",  # some-org/sketchy-action@main (branch)
        "GHA-022",  # actions/checkout@v3 (first-party not SHA)
        "GHA-030",  # self-hosted on pull_request
        "GHA-032",  # script injection via PR title
        "GHA-040",  # no timeout-minutes
    ]
    seen_ids = {f.id for f in bad_findings}
    for eid in expected_ids:
        marker = "OK " if eid in seen_ids else "MISS"
        print(f"  {marker} {eid}")

    miss = [eid for eid in expected_ids if eid not in seen_ids]
    extra = sorted(seen_ids - set(expected_ids))

    print(f"\nBad fixture: {len(bad_findings)} total findings (expected ~{len(expected_ids)}-15)")
    print(f"Good fixture: {len(good_findings)} total findings (expected 0)")
    print(f"Expected IDs hit: {len(expected_ids) - len(miss)}/{len(expected_ids)}")
    if miss:
        print(f"MISSING from bad: {miss}")
    if extra:
        print(f"Extras seen on bad: {extra}")

    print("\n" + "=" * 70)
    print("MCP SERVER TOOL REGISTRATION CHECK")
    print("=" * 70)
    from gha_audit.main import get_server
    server = get_server()
    tools = await server.list_tools()
    print(f"Server: {server.name}")
    print(f"Tools registered: {len(tools)}")
    for t in tools:
        print(f"  - {t.name}")

    return 0 if not miss else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
