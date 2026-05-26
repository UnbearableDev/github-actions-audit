"""Action pinning checks (GHA-020 to GHA-023)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from gha_audit.findings import Finding, WorkflowDoc, check_meta

CATEGORY = "action_pinning"

# 40-char hex = SHA pin (good)
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
# vN or vN.N.N = tag pin (acceptable for first-party, risky for 3rd-party)
TAG_RE = re.compile(r"^v?\d+(\.\d+)*([-+a-zA-Z0-9.]*)?$")

# First-party owner namespaces (Microsoft/GitHub-owned)
FIRST_PARTY_OWNERS = {"actions", "github"}


def _parse_uses(uses: str) -> tuple[str, str, str] | None:
    """Split `owner/repo[/path]@ref` into (owner, repo, ref). Returns None if not a uses ref."""
    if not isinstance(uses, str) or "@" not in uses:
        return None
    if uses.startswith("./") or uses.startswith("docker://"):
        return None  # local action or docker — not a registry ref
    ref_part = uses.split("@", 1)
    repo_full, ref = ref_part[0], ref_part[1]
    parts = repo_full.split("/")
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1]
    return owner, repo, ref


@check_meta(id="GHA-020", severity="high", title="Third-party action pinned to mutable tag")
def check_third_party_tag_pin(doc: WorkflowDoc) -> Iterable[Finding]:
    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses")
        parsed = _parse_uses(uses) if isinstance(uses, str) else None
        if not parsed:
            continue
        owner, repo, ref = parsed
        if owner in FIRST_PARTY_OWNERS:
            continue
        if SHA_RE.match(ref):
            continue
        # We treat any non-SHA ref as a tag (or branch) — both are mutable
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-020",
            category=CATEGORY,
            severity="high",
            job=jname,
            step=step_name,
            title=f"Third-party action `{owner}/{repo}` pinned by tag, not SHA",
            description=(
                f"`uses: {uses}` pins to `{ref!r}`. Third-party action tags are "
                "mutable — the owner can retag a release to point at malicious "
                "code, and your next workflow run pulls it. Several 2024 "
                "supply-chain incidents (tj-actions/changed-files) used this vector."
            ),
            remediation=(
                f"Pin to the commit SHA instead: `{owner}/{repo}@<40-char-sha>`. "
                "Use Dependabot or Renovate to auto-bump SHAs."
            ),
            fix_yaml_snippet=f"      - uses: {owner}/{repo}@<sha>  # was: {ref}",
            references=["GHA-Action-Pinning"],
        )


@check_meta(id="GHA-021", severity="high", title="Third-party action pinned to mutable branch")
def check_third_party_branch_pin(doc: WorkflowDoc) -> Iterable[Finding]:
    """Subset of GHA-020 — branches like @main / @master are the worst case."""
    risky_branches = {"main", "master", "develop", "dev", "trunk"}
    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses")
        parsed = _parse_uses(uses) if isinstance(uses, str) else None
        if not parsed:
            continue
        owner, repo, ref = parsed
        if owner in FIRST_PARTY_OWNERS:
            continue
        if ref not in risky_branches:
            continue
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-021",
            category=CATEGORY,
            severity="high",
            job=jname,
            step=step_name,
            title=f"Third-party action `{owner}/{repo}` pinned to branch `{ref}`",
            description=(
                f"`uses: {uses}` pins to a branch ref. Every workflow run pulls "
                "the latest commit on that branch — an attacker who compromises "
                "the upstream repo can deliver arbitrary code into your workflow "
                "instantly. Branches are the worst case of unpinned references."
            ),
            remediation=f"Pin to a specific commit SHA: `{owner}/{repo}@<40-char-sha>`.",
            fix_yaml_snippet=f"      - uses: {owner}/{repo}@<sha>  # was: {ref}",
            references=["GHA-Action-Pinning"],
        )


@check_meta(id="GHA-022", severity="medium", title="First-party action (`actions/*`) not SHA-pinned")
def check_first_party_unpinned(doc: WorkflowDoc) -> Iterable[Finding]:
    """First-party actions (actions/*, github/*) are lower-risk but still
    recommended to pin for reproducibility. Severity is medium, not high."""
    for jname, idx, step in doc.iter_steps():
        uses = step.get("uses")
        parsed = _parse_uses(uses) if isinstance(uses, str) else None
        if not parsed:
            continue
        owner, repo, ref = parsed
        if owner not in FIRST_PARTY_OWNERS:
            continue
        if SHA_RE.match(ref):
            continue
        step_name = step.get("name") or f"step #{idx + 1}"
        yield Finding(
            id="GHA-022",
            category=CATEGORY,
            severity="medium",
            job=jname,
            step=step_name,
            title=f"First-party action `{owner}/{repo}@{ref}` not SHA-pinned",
            description=(
                f"`uses: {uses}` is from {owner}/* (first-party, lower risk) but "
                "still pinned by tag. GitHub has retracted tags in the past for "
                "security reasons. Pinning to SHA gives perfect reproducibility."
            ),
            remediation=(
                f"Pin to commit SHA: `{owner}/{repo}@<40-char-sha>`. Less urgent "
                "than third-party SHA pinning, but recommended for production."
            ),
            references=["GHA-Action-Pinning"],
        )


CHECKS = [
    check_third_party_tag_pin,
    check_third_party_branch_pin,
    check_first_party_unpinned,
]
