"""Permissions checks (GHA-010 to GHA-013)."""

from __future__ import annotations

from collections.abc import Iterable

from gha_audit.findings import Finding, WorkflowDoc, check_meta

CATEGORY = "permissions"


def _permissions_is_write_all(perms) -> bool:
    """`permissions: write-all` or all subkeys set to write."""
    if perms == "write-all":
        return True
    if not isinstance(perms, dict):
        return False
    return all(v == "write" for v in perms.values()) and bool(perms)


@check_meta(id="GHA-010", severity="high", title="`permissions: write-all` granted")
def check_write_all(doc: WorkflowDoc) -> Iterable[Finding]:
    """Either at workflow root or any job: write-all is a strong red flag."""
    if _permissions_is_write_all(doc.workflow_permissions):
        yield Finding(
            id="GHA-010",
            category=CATEGORY,
            severity="high",
            title="Workflow grants `permissions: write-all`",
            description=(
                "The workflow's `permissions:` block grants write access to every "
                "scope. `GITHUB_TOKEN` issued to this workflow can push code, "
                "create releases, write packages, modify Actions, etc. A compromised "
                "step (script injection, malicious action) gets full repo control."
            ),
            remediation=(
                "Replace with the minimum set of scopes you actually need. Default "
                "to `permissions: read-all` or `permissions: {}` and add specific "
                "write scopes per job as needed."
            ),
            fix_yaml_snippet="permissions: read-all  # then grant write per job",
            references=["GHA-Permissions-Docs"],
        )

    for jname, job in doc.iter_jobs():
        if _permissions_is_write_all(job.get("permissions")):
            yield Finding(
                id="GHA-010",
                category=CATEGORY,
                severity="high",
                job=jname,
                title=f"Job '{jname}' grants `permissions: write-all`",
                description=(
                    f"Job '{jname}' overrides the workflow permissions with `write-all`. "
                    "Same risk as the workflow-level case."
                ),
                remediation="Grant only the specific scopes the job needs.",
                fix_yaml_snippet=(
                    "    permissions:\n"
                    "      contents: read\n"
                    "      packages: write  # only if you actually publish"
                ),
                references=["GHA-Permissions-Docs"],
            )


@check_meta(id="GHA-011", severity="medium", title="No top-level `permissions:` (inherits broad default)")
def check_no_top_level_permissions(doc: WorkflowDoc) -> Iterable[Finding]:
    """If no permissions block exists at workflow or job level, GITHUB_TOKEN
    inherits the repository's default — historically `write-all` for most repos."""
    if doc.workflow_permissions is not None:
        return  # explicit at workflow level — fine
    # Check if every job sets its own permissions
    all_jobs_scoped = doc.jobs and all(
        job.get("permissions") is not None for job in doc.jobs.values()
    )
    if all_jobs_scoped:
        return  # all jobs scope individually — fine
    yield Finding(
        id="GHA-011",
        category=CATEGORY,
        severity="medium",
        title="No top-level `permissions:` block",
        description=(
            "Workflow has no top-level `permissions:` and not every job overrides "
            "it. `GITHUB_TOKEN` issued to this workflow inherits the repository's "
            "default token permission — for repos created before Feb 2023 this is "
            "`write-all`. A compromised step gets full repo write access."
        ),
        remediation=(
            "Add `permissions: read-all` at the top of the workflow (or "
            "`permissions: {}` for maximum lockdown). Then grant specific write "
            "scopes per job that needs them."
        ),
        fix_yaml_snippet=(
            "# at workflow root:\n"
            "permissions: read-all\n"
            "# or fully empty:\n"
            "# permissions: {}"
        ),
        references=["GHA-Permissions-Docs", "GHA-Default-Token-Permissions"],
    )


@check_meta(id="GHA-013", severity="high", title="`pull_request_target` + checkout = PWNing pattern")
def check_pull_request_target_with_checkout(doc: WorkflowDoc) -> Iterable[Finding]:
    """The classic supply-chain-attack pattern: pull_request_target trigger
    PLUS actions/checkout from the PR head = arbitrary fork code runs with
    write permissions on the base repo."""
    on = doc.on
    triggers: list[str] = []
    if isinstance(on, str):
        triggers = [on]
    elif isinstance(on, list):
        triggers = [str(t) for t in on if isinstance(t, str)]
    elif isinstance(on, dict):
        triggers = list(on.keys())

    if "pull_request_target" not in triggers:
        return

    # Now check if any job uses actions/checkout with PR head ref
    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses") or ""
        if not isinstance(uses, str):
            continue
        if not uses.startswith("actions/checkout"):
            continue
        with_block = step.get("with") or {}
        ref = with_block.get("ref") if isinstance(with_block, dict) else None
        # The dangerous patterns
        if isinstance(ref, str) and (
            "github.event.pull_request.head" in ref
            or "github.head_ref" in ref
        ):
            step_name = step.get("name") or f"step #{idx + 1}"
            yield Finding(
                id="GHA-013",
                category=CATEGORY,
                severity="high",
                job=jname,
                step=step_name,
                title="`pull_request_target` + checkout of PR head = code execution risk",
                description=(
                    f"Job '{jname}', step '{step_name}': the workflow triggers on "
                    "`pull_request_target` (which runs with the BASE repo's "
                    "secrets/permissions) AND checks out the PR head ref — that's "
                    "untrusted fork code. A malicious PR can run arbitrary code "
                    "with full base-repo token permissions. This is the pattern "
                    "behind several 2024–2025 supply-chain incidents."
                ),
                remediation=(
                    "Either: (a) switch the trigger to `pull_request` (which runs "
                    "with PR-fork's reduced permissions) and accept fewer secrets "
                    "access, or (b) keep `pull_request_target` but DO NOT check "
                    "out the PR head — only the base branch."
                ),
                fix_yaml_snippet=(
                    "# Option A — safer trigger:\n"
                    "on:\n"
                    "  pull_request:\n"
                    "# Option B — keep trigger, don't checkout head:\n"
                    "      - uses: actions/checkout@<sha>  # NO `ref:` arg"
                ),
                references=["GHA-pull_request_target-Risk"],
            )


CHECKS = [
    check_write_all,
    check_no_top_level_permissions,
    check_pull_request_target_with_checkout,
]
