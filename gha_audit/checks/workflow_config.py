"""Workflow-level config checks (GHA-040 to GHA-044)."""

from __future__ import annotations

from collections.abc import Iterable

from gha_audit.findings import Finding, WorkflowDoc, check_meta

CATEGORY = "workflow_config"


@check_meta(id="GHA-040", severity="low", title="No `timeout-minutes` on job")
def check_no_timeout(doc: WorkflowDoc) -> Iterable[Finding]:
    """Default job timeout is 360 minutes. A runaway job (or a malicious step
    that's hanging deliberately to consume credits) can burn an absurd amount
    of compute before failing."""
    for jname, job in doc.iter_jobs():
        if job.get("timeout-minutes") is not None:
            continue
        # Check if all steps have step-level timeouts (rare — but acceptable)
        steps = job.get("steps") or []
        if isinstance(steps, list) and steps and all(
            isinstance(s, dict) and s.get("timeout-minutes") is not None
            for s in steps
        ):
            continue
        yield Finding(
            id="GHA-040",
            category=CATEGORY,
            severity="low",
            job=jname,
            title=f"Job '{jname}' has no `timeout-minutes`",
            description=(
                f"Job '{jname}' has no `timeout-minutes` set. Default timeout is "
                "360 minutes (6 hours). A hung or runaway step can burn that "
                "much compute before failing — meaningful on private runners or "
                "paid plans."
            ),
            remediation=(
                "Add `timeout-minutes:` at the job level. Most CI jobs should "
                "complete in under 30 min; pick a value that's 2-3x your typical "
                "runtime."
            ),
            fix_yaml_snippet="    timeout-minutes: 30",
            references=["GHA-Workflow-Syntax-Timeout"],
        )


CHECKS = [
    check_no_timeout,
]
