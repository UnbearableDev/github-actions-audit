"""Input resolution + YAML parsing for GitHub Actions workflows."""

from __future__ import annotations

import io

import httpx
import yaml

from gha_audit.findings import WorkflowDoc

MAX_BYTES = 500_000  # 500 KB cap
FETCH_TIMEOUT = httpx.Timeout(5.0)
MAX_REDIRECTS = 3


class WorkflowInputError(ValueError):
    pass


async def resolve_workflow_input(
    workflow_yaml: str | None,
    workflow_url: str | None,
) -> WorkflowDoc:
    if workflow_yaml and workflow_url:
        text = workflow_yaml
    elif workflow_yaml:
        text = workflow_yaml
    elif workflow_url:
        text = await _fetch_url(workflow_url)
    else:
        raise WorkflowInputError(
            "Provide either `workflow_yaml` or `workflow_url`."
        )
    return _parse(text)


async def _fetch_url(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        raise WorkflowInputError(f"workflow_url must be HTTP(S), got: {url!r}")
    try:
        async with httpx.AsyncClient(
            timeout=FETCH_TIMEOUT,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as e:
        raise WorkflowInputError(f"Failed to fetch workflow_url: {e}") from e
    if len(resp.content) > MAX_BYTES:
        raise WorkflowInputError(f"Fetched content exceeds {MAX_BYTES} bytes.")
    return resp.text


def _parse(text: str) -> WorkflowDoc:
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise WorkflowInputError(f"Workflow exceeds {MAX_BYTES} bytes.")
    if not text.strip():
        raise WorkflowInputError("Workflow YAML is empty.")

    try:
        loaded = yaml.safe_load(io.StringIO(text))
    except yaml.YAMLError as e:
        raise WorkflowInputError(f"Invalid YAML: {e}") from e

    if loaded is None:
        raise WorkflowInputError("YAML parsed to None.")
    if not isinstance(loaded, dict):
        raise WorkflowInputError(
            f"Expected a YAML mapping at top level, got {type(loaded).__name__}."
        )

    # YAML 1.1 boolean-aliasing: GitHub Actions uses `on:` as a key, which
    # PyYAML's default loader parses as the boolean True. Fix it back to "on".
    if True in loaded:
        loaded["on"] = loaded.pop(True)

    return WorkflowDoc(raw=loaded, raw_text=text)
