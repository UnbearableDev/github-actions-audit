"""Secret-leakage checks (GHA-001 to GHA-006)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from gha_audit.findings import Finding, WorkflowDoc, check_meta

CATEGORY = "secrets"

# Match `${{ ... secrets.NAME ... }}` — secret access anywhere inside an expression,
# not just bare access. Catches `${{ secrets.X }}`, `${{ secrets.X == 'y' }}`, etc.
SECRET_EXPR_RE = re.compile(r"\$\{\{[^}]*\bsecrets\.[A-Za-z_][A-Za-z0-9_]*\b[^}]*\}\}")
SECRET_NAME_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_\-]?key|access[_\-]?key|"
    r"private[_\-]?key|auth|credential|bearer|jwt)"
)
ENVVAR_REF_RE = re.compile(r"^\$\{?\{?[A-Za-z_][A-Za-z0-9_.]*[\s}]*\}?\}?$")
PLACEHOLDER_RE = re.compile(r"(?i)^(your[_\-]?|changeme|placeholder|fixme|<.*>)")


def _step_env(step: dict) -> dict:
    env = step.get("env")
    return env if isinstance(env, dict) else {}


def _job_env(job: dict) -> dict:
    env = job.get("env")
    return env if isinstance(env, dict) else {}


@check_meta(id="GHA-001", severity="high", title="Secret used directly in `run:` (logs at risk)")
def check_secret_in_run_unmasked(doc: WorkflowDoc) -> Iterable[Finding]:
    """Detect ${{ secrets.X }} interpolated directly into a run: script.

    The risk: the shell receives the literal secret value, which can land in
    logs via `set -x`, `echo`, error output, or process listings.
    The correct pattern is to pass via env: and read via $VAR_NAME inside run:
    """
    for jname, idx, step in doc.iter_steps():
        run = step.get("run")
        if not isinstance(run, str):
            continue
        if SECRET_EXPR_RE.search(run):
            step_name = step.get("name") or f"step #{idx + 1}"
            yield Finding(
                id="GHA-001",
                category=CATEGORY,
                severity="high",
                job=jname,
                step=step_name,
                title="Secret interpolated directly into `run:` script",
                description=(
                    f"Job '{jname}', step '{step_name}': the `run:` block contains "
                    f"`${{{{ secrets.X }}}}` interpolation. The literal secret value "
                    f"reaches the shell — it can leak via `set -x`, error output, "
                    f"or process listings."
                ),
                remediation=(
                    "Pass the secret via `env:` and read it from the environment "
                    "variable inside `run:`. GitHub auto-masks env-passed secrets "
                    "in logs."
                ),
                fix_yaml_snippet=(
                    "      env:\n"
                    "        MY_SECRET: ${{ secrets.MY_SECRET }}\n"
                    "      run: |\n"
                    "        # use $MY_SECRET, not ${{ secrets.MY_SECRET }}\n"
                    "        do-something --token \"$MY_SECRET\""
                ),
                references=["GHA-Security-Hardening"],
            )


@check_meta(id="GHA-002", severity="high", title="Secret printed via echo / set-output")
def check_secret_echoed(doc: WorkflowDoc) -> Iterable[Finding]:
    """Detect `echo "$SECRET"` or `echo "${{ secrets.X }}"` or set-output with a secret."""
    echo_re = re.compile(
        r"(?i)\b(echo|printf|cat\s+<<|::set-output|>>\s*\$GITHUB_OUTPUT)\b.*\$\{\{\s*secrets\."
    )
    for jname, idx, step in doc.iter_steps():
        run = step.get("run")
        if not isinstance(run, str):
            continue
        if echo_re.search(run):
            step_name = step.get("name") or f"step #{idx + 1}"
            yield Finding(
                id="GHA-002",
                category=CATEGORY,
                severity="high",
                job=jname,
                step=step_name,
                title="Secret printed to stdout / set-output",
                description=(
                    f"Job '{jname}', step '{step_name}': the script appears to "
                    "`echo`, `printf`, or `set-output` a `${{ secrets.X }}` value. "
                    "Anything written to stdout lands in the job log; anything in "
                    "set-output lands in subsequent jobs' inputs (also logged)."
                ),
                remediation=(
                    "Never log secret values. If you need to pass a secret to a "
                    "later step, use the `env:` keyword (auto-masked) or the "
                    "actions/cache built-in."
                ),
                references=["GHA-Security-Hardening"],
            )


@check_meta(id="GHA-003", severity="medium", title="Secret referenced in `if:` condition")
def check_secret_in_if(doc: WorkflowDoc) -> Iterable[Finding]:
    """if: contexts get logged in the workflow run history."""
    for jname, idx, step in doc.iter_steps():
        cond = step.get("if")
        if not isinstance(cond, str):
            continue
        if SECRET_EXPR_RE.search(cond):
            step_name = step.get("name") or f"step #{idx + 1}"
            yield Finding(
                id="GHA-003",
                category=CATEGORY,
                severity="medium",
                job=jname,
                step=step_name,
                title="Secret used in `if:` condition",
                description=(
                    f"Job '{jname}', step '{step_name}': `if:` references "
                    "`${{ secrets.X }}`. The evaluated `if:` expression is "
                    "displayed in the workflow run UI — pattern matches on "
                    "secret values are visible to anyone with read access to "
                    "the repo's Actions tab."
                ),
                remediation=(
                    "Pass the secret to `env:` and condition on a non-secret "
                    "boolean derived from it (e.g. set `env: HAS_SECRET: ${{ "
                    "secrets.X != '' }}` at the job level, then `if: env.HAS_SECRET == 'true'`)."
                ),
                references=["GHA-Security-Hardening"],
            )


@check_meta(id="GHA-004", severity="high", title="Hardcoded credential pattern in env:")
def check_hardcoded_env(doc: WorkflowDoc) -> Iterable[Finding]:
    """Detect literal secret values in env: at job or step level (not ${{ secrets.X }} refs)."""
    def emit_for(scope_label: str, jname: str, env: dict, step_name: str | None = None):
        for key, val in env.items():
            if val is None:
                continue
            s = str(val).strip()
            if not s:
                continue
            if not SECRET_NAME_RE.search(str(key)):
                continue
            if SECRET_EXPR_RE.search(s):
                continue  # legitimate ${{ secrets.X }} reference
            if ENVVAR_REF_RE.match(s):
                continue  # ${VAR} or ${{ env.VAR }}
            if PLACEHOLDER_RE.match(s):
                continue
            yield Finding(
                id="GHA-004",
                category=CATEGORY,
                severity="high",
                job=jname,
                step=step_name,
                title=f"Hardcoded secret in {scope_label} env: ({key})",
                description=(
                    f"`env: {key}=<literal>` at {scope_label} level. Workflow YAML "
                    "is committed to git — literal secrets in YAML end up in "
                    "history, CI logs, and any PR that touches the file."
                ),
                remediation=(
                    f"Move the value to GitHub Secrets and reference as "
                    f"`{key}: ${{{{ secrets.{key} }}}}`."
                ),
                fix_yaml_snippet=f"      env:\n        {key}: ${{{{ secrets.{key} }}}}",
                references=["GHA-Encrypted-Secrets"],
            )

    for jname, job in doc.iter_jobs():
        yield from emit_for("job", jname, _job_env(job))
        steps = job.get("steps") or []
        if isinstance(steps, list):
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                step_name = step.get("name") or f"step #{idx + 1}"
                yield from emit_for("step", jname, _step_env(step), step_name)


CHECKS = [
    check_secret_in_run_unmasked,
    check_secret_echoed,
    check_secret_in_if,
    check_hardcoded_env,
]
