"""Core data types: Finding + WorkflowDoc + check_meta decorator."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["high", "medium", "low", "info"]

SEVERITY_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}


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
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "fix_yaml_snippet": self.fix_yaml_snippet,
            "references": self.references,
        }


@dataclass
class WorkflowDoc:
    """Parsed GitHub Actions workflow with helpers."""
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
        # Parser fixes this — see parser.py — so we just read by string key here.
        return self.raw.get("on")

    @property
    def workflow_permissions(self) -> Any:
        return self.raw.get("permissions")

    def iter_jobs(self) -> Iterator[tuple[str, dict[str, Any]]]:
        for name, job in self.jobs.items():
            yield name, job

    def iter_steps(self) -> Iterator[tuple[str, int, dict[str, Any]]]:
        """Yield (job_name, step_index, step_dict)."""
        for jname, job in self.iter_jobs():
            steps = job.get("steps") or []
            if not isinstance(steps, list):
                continue
            for idx, step in enumerate(steps):
                if isinstance(step, dict):
                    yield jname, idx, step


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
