"""Core data types: Finding + WorkflowDoc + check_meta decorator.

Line-number extraction
----------------------
ruamel.yaml in round-trip mode attaches a `.lc` (line/column) object to
CommentedMap and CommentedSeq nodes.

  - For a mapping node `m`, `m.lc.line` is the line of the opening `{` or
    the first key (0-indexed). `m.lc.data[key]` returns `(line, col)` for
    the position of `key` itself (0-indexed).
  - For a sequence node `s`, `s.lc.data[i]` returns `(line, col)` of the
    i-th item.

Use `node_line(node, key)` to get 1-indexed source lines safely.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def node_line(node: Any, key: Any = None) -> int | None:
    """Return the 1-indexed source line for a ruamel.yaml node.

    Args:
        node: A CommentedMap, CommentedSeq, or scalar. If it has no .lc,
              returns None (safe for plain-dict fallback).
        key:  When given, look up the key's position within a mapping
              (`node.lc.data[key][0]`) rather than the node's own line.

    Returns:
        1-indexed line number, or None if position info is unavailable.
    """
    lc = getattr(node, "lc", None)
    if lc is None:
        return None
    try:
        if key is not None:
            data = getattr(lc, "data", None)
            if data and key in data:
                return data[key][0] + 1  # ruamel is 0-indexed
        raw_line = getattr(lc, "line", None)
        if raw_line is not None:
            return raw_line + 1
    except Exception:
        pass
    return None


def node_col(node: Any, key: Any = None) -> int | None:
    """Return the 1-indexed source column for a ruamel.yaml node/key."""
    lc = getattr(node, "lc", None)
    if lc is None:
        return None
    try:
        if key is not None:
            data = getattr(lc, "data", None)
            if data and key in data:
                return data[key][1] + 1  # ruamel is 0-indexed
        raw_col = getattr(lc, "col", None)
        if raw_col is not None:
            return raw_col + 1
    except Exception:
        pass
    return None


@dataclass
class Finding:
    id: str
    category: str
    severity: Severity
    title: str
    description: str
    remediation: str
    job: str | None = None
    step: str | None = None
    line_number: int | None = None
    column_number: int | None = None
    fix_yaml_snippet: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "job": self.job,
            "step": self.step,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "fix_yaml_snippet": self.fix_yaml_snippet,
            "references": self.references,
        }


@dataclass
class WorkflowDoc:
    """Parsed GitHub Actions workflow with helpers.

    `raw` is a ruamel.yaml CommentedMap (subclass of dict) so all existing
    dict-style access continues to work. Nodes carry .lc for line/col info.
    """
    raw: dict[str, Any]
    raw_text: str

    @property
    def name(self) -> str | None:
        n = self.raw.get("name")
        return str(n) if n else None

    @property
    def jobs(self) -> dict[str, dict[str, Any]]:
        j = self.raw.get("jobs") or {}
        return {k: (v if isinstance(v, dict) else {}) for k, v in j.items()}

    @property
    def on(self) -> Any:
        # YAML 1.1 boolean-aliasing: "on:" key may have been parsed as True.
        # ruamel round-trip mode preserves the literal string key "on", so
        # this is defensive only.
        return self.raw.get("on")

    @property
    def workflow_permissions(self) -> Any:
        return self.raw.get("permissions")

    def iter_jobs(self) -> Iterator[tuple[str, dict[str, Any]]]:
        for name, job in self.jobs.items():
            yield name, job

    def iter_steps(self) -> Iterator[tuple[str, int, dict[str, Any]]]:
        """Yield (job_name, step_index, step_dict).

        step_dict is the raw ruamel CommentedMap node so callers can call
        node_line(step, key) to get source positions.
        """
        for jname, job in self.iter_jobs():
            steps = job.get("steps") or []
            if not isinstance(steps, list):
                continue
            for idx, step in enumerate(steps):
                if isinstance(step, dict):
                    yield jname, idx, step

    def raw_jobs_node(self) -> Any:
        """Return the raw ruamel CommentedMap for the top-level 'jobs' key."""
        return self.raw.get("jobs")


def check_meta(*, id: str, severity: Severity, title: str) -> Callable:
    def decorator(fn):
        fn.__check_meta__ = {"id": id, "severity": severity, "title": title}
        return fn
    return decorator


def filter_by_min_severity(findings: list[Finding], min_severity: Severity) -> list[Finding]:
    threshold = SEVERITY_RANK[min_severity]
    return [f for f in findings if SEVERITY_RANK[f.severity] >= threshold]


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_sev = {"high": 0, "medium": 0, "low": 0, "info": 0}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {
        "total_findings": len(findings),
        "by_severity": by_sev,
        "by_category": by_cat,
    }
