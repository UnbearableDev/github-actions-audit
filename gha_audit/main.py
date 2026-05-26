"""GitHub Actions Security Audit — MCP server."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Mapping, MutableMapping
from typing import Any, Literal

import uvicorn
from apify import Actor
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.types import Receive, Scope, Send

from gha_audit import checks as check_registry
from gha_audit.findings import (
    Finding,
    WorkflowDoc,
    filter_by_min_severity,
    summarize,
)
from gha_audit.parser import WorkflowInputError, resolve_workflow_input

Severity = Literal["high", "medium", "low", "info"]
DEFAULT_MIN_SEVERITY: Severity = "low"


LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GitHub Actions Audit — MCP server</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 680px; margin: 60px auto; padding: 0 24px; line-height: 1.55;
         color: #1a1a1a; background: #fafafa; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem 0; }
  .sub { color: #666; margin: 0 0 2rem 0; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
              background: #efefef; padding: 2px 6px; border-radius: 3px; font-size: .9rem; }
  pre { padding: 12px; overflow-x: auto; }
  a { color: #0366d6; text-decoration: none; }
  a:hover { text-decoration: underline; }
  footer { margin-top: 3rem; font-size: .85rem; color: #888; }
  ul { padding-left: 1.2rem; } li { margin: .35rem 0; }
</style>
</head>
<body>
<h1>GitHub Actions Security Audit — MCP server</h1>
<p class="sub">This is a Model Context Protocol endpoint, not a website.</p>

<p>Point your MCP client at the <code>/mcp</code> path:</p>
<pre>POST /mcp     (Streamable HTTP transport)</pre>

<p>Catches script injection, leaked tokens, unpinned actions, and broad-permission risks before they merge.</p>

<p><strong>Quick links:</strong></p>
<ul>
  <li><a href="https://apify.com/unbearable_dev/github-actions-audit">Apify Store listing</a></li>
  <li><a href="https://github.com/UnbearableDev/github-actions-audit">GitHub source</a></li>
</ul>

<footer>Built by Unbearable TechTips. Sibling MCPs: <a href="https://apify.com/unbearable_dev/docker-compose-audit">docker-compose-audit</a>, <a href="https://apify.com/unbearable_dev/dockerfile-audit">dockerfile-audit</a>.</footer>
</body>
</html>
""".encode("utf-8")


def _findings_to_response(findings: list[Finding], doc: WorkflowDoc, label: str) -> dict[str, Any]:
    summary = summarize(findings)
    return {
        "type": "text",
        "text": (
            f"{label}: {summary['total_findings']} findings "
            f"({summary['by_severity']['high']} high, "
            f"{summary['by_severity']['medium']} medium, "
            f"{summary['by_severity']['low']} low, "
            f"{summary['by_severity']['info']} info)."
        ),
        "structuredContent": {
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
            "workflow_metadata": {
                "name": doc.name,
                "job_count": len(doc.jobs),
                "triggers": list(doc.on.keys()) if isinstance(doc.on, dict) else doc.on,
            },
        },
    }


def _error_response(message: str) -> dict[str, Any]:
    return {
        "type": "text",
        "text": f"Audit failed: {message}",
        "structuredContent": {"error": message, "findings": []},
    }


def get_server() -> FastMCP:
    server = FastMCP("github-actions-audit", "0.1.0")

    async def _run_audit(
        workflow_yaml: str | None,
        workflow_url: str | None,
        min_severity: Severity,
        category: str | None,
    ) -> dict[str, Any]:
        await Actor.charge("audit-call")
        try:
            doc = await resolve_workflow_input(workflow_yaml, workflow_url)
        except WorkflowInputError as e:
            return _error_response(str(e))

        if category is None:
            findings = check_registry.run_all(doc)
            label = "Full audit"
        else:
            try:
                findings = check_registry.run_category(category, doc)
            except ValueError as e:
                return _error_response(str(e))
            label = f"Category {category!r}"

        findings = filter_by_min_severity(findings, min_severity)
        Actor.log.info(
            f"{label}: {len(findings)} findings (min_severity={min_severity}) "
            f"across {len(doc.jobs)} jobs"
        )
        return _findings_to_response(findings, doc, label)

    @server.tool()
    async def audit_workflow(
        workflow_yaml: str | None = None,
        workflow_url: str | None = None,
        min_severity: Severity = DEFAULT_MIN_SEVERITY,
    ) -> dict[str, Any]:
        """Run the full security audit against a GitHub Actions workflow.

        Provide exactly one of `workflow_yaml` (paste the YAML content) or
        `workflow_url` (HTTPS URL — e.g. a GitHub raw URL to a single
        `.github/workflows/*.yml` file). Returns findings with severity,
        affected job/step, remediation text, and a YAML fix snippet.

        Args:
            workflow_yaml: The workflow YAML content as a string.
            workflow_url: HTTPS URL to a workflow file (5s timeout, 500KB cap).
            min_severity: Drop findings below this severity. One of 'info', 'low', 'medium', 'high'. Default 'low'.
        """
        return await _run_audit(workflow_yaml, workflow_url, min_severity, None)

    def _make_category_tool(category: str):
        async def _tool(
            workflow_yaml: str | None = None,
            workflow_url: str | None = None,
            min_severity: Severity = DEFAULT_MIN_SEVERITY,
        ) -> dict[str, Any]:
            return await _run_audit(workflow_yaml, workflow_url, min_severity, category)
        _tool.__name__ = f"check_{category}"
        _tool.__doc__ = (
            f"Run only the {category} checks against a workflow.\n\n"
            "Args: workflow_yaml or workflow_url, min_severity (default 'low')."
        )
        return _tool

    for category in check_registry.ALL_CATEGORIES:
        server.tool()(_make_category_tool(category))

    @server.tool()
    async def list_checks(category: str | None = None) -> dict[str, Any]:
        """List the full catalog of available checks."""
        await Actor.charge("list-checks")
        catalog = check_registry.catalog()
        if category is not None:
            catalog = [c for c in catalog if c["category"] == category]
        return {
            "type": "text",
            "text": f"{len(catalog)} checks across {len(check_registry.ALL_CATEGORIES)} categories.",
            "structuredContent": {
                "categories": check_registry.ALL_CATEGORIES,
                "checks": catalog,
            },
        }

    @server.resource(
        uri="https://unbearabletechtips.com/github-actions-audit",
        name="about",
    )
    def about() -> str:
        return (
            "GitHub Actions Security Audit — MCP server by Unbearable TechTips.\n"
            "Catches supply-chain risks, leaked tokens, broad permissions, and "
            "script-injection patterns in .github/workflows/*.yml files.\n\n"
            f"Categories: {', '.join(check_registry.ALL_CATEGORIES)}\n"
            f"Total checks: {len(check_registry.catalog())}\n\n"
            "Pricing: pay-per-event ($0.02 per audit, $0.005 for catalog discovery)."
        )

    return server


# ── Session middleware (verbatim from dockerfile-audit) ─────────────────────


def get_session_id(headers: Mapping[str, str]) -> str | None:
    for key in ("mcp-session-id", "mcp_session_id"):
        if value := headers.get(key):
            return value
    return None


class SessionTrackingMiddleware:
    def __init__(self, app: Any, port: int, timeout_secs: int) -> None:
        self.app = app
        self.port = port
        self.timeout_secs = timeout_secs
        self._last_activity: dict[str, float] = {}
        self._timers: dict[str, asyncio.Task[None]] = {}

    def _session_cleanup(self, sid: str) -> None:
        self._last_activity.pop(sid, None)
        if (timer := self._timers.pop(sid, None)) and not timer.done():
            timer.cancel()

    def _touch(self, sid: str) -> None:
        self._last_activity[sid] = time.time()
        if (timer := self._timers.get(sid)) and not timer.done():
            timer.cancel()

        async def close_if_idle() -> None:
            try:
                await asyncio.sleep(self.timeout_secs)
                elapsed = time.time() - self._last_activity.get(sid, 0)
                if elapsed < self.timeout_secs * 0.9:
                    return
                Actor.log.info(f"Closing idle session: {sid}")
                scope: Scope = {
                    "type": "http", "http_version": "1.1", "method": "DELETE",
                    "scheme": "http", "path": "/mcp", "raw_path": b"/mcp",
                    "query_string": b"",
                    "headers": [(b"mcp-session-id", sid.encode())],
                    "server": ("127.0.0.1", self.port),
                    "client": ("127.0.0.1", 0),
                    "_idle_close": True,
                }
                async def noop_receive(): return {"type": "http.request", "body": b"", "more_body": False}
                async def noop_send(_): pass
                await self(scope, noop_receive, noop_send)
                self._session_cleanup(sid)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                Actor.log.exception(f"Failed to close idle session {sid}: {e}")

        self._timers[sid] = asyncio.create_task(close_if_idle())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")

        if (scope.get("type") == "http" and scope.get("method") == "GET" and path in ("", "/")):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"cache-control", b"public, max-age=3600"),
                ],
            })
            await send({"type": "http.response.body", "body": LANDING_HTML})
            return

        if scope.get("type") != "http" or path not in ("/mcp", "/mcp/"):
            await self.app(scope, receive, send)
            return

        if scope.get("_idle_close"):
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        sid = get_session_id(request.headers)
        is_delete = scope.get("method") == "DELETE"

        if sid and not is_delete:
            self._touch(sid)

        new_sid: str | None = None

        async def capture_send(msg: MutableMapping[str, Any]) -> None:
            nonlocal new_sid
            if msg.get("type") == "http.response.start":
                for k, v in msg.get("headers", []):
                    if k.decode().lower() == "mcp-session-id":
                        new_sid = v.decode()
                        break
            await send(msg)

        await self.app(scope, receive, capture_send)

        if not sid and new_sid:
            Actor.log.info(f"New session: {new_sid}")
            self._touch(new_sid)

        if is_delete and sid:
            Actor.log.info(f"Session closed: {sid}")
            self._session_cleanup(sid)


async def main() -> None:
    await Actor.init()
    port = int(os.environ.get("APIFY_CONTAINER_PORT", "3000"))
    timeout_secs = int(os.environ.get("SESSION_TIMEOUT_SECS", "300"))

    server = get_server()
    app = server.http_app(transport="streamable-http")
    app = SessionTrackingMiddleware(app=app, port=port, timeout_secs=timeout_secs)

    try:
        Actor.log.info(f"Starting github-actions-audit on port {port}")
        config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")  # noqa: S104
        await uvicorn.Server(config).serve()
    except KeyboardInterrupt:
        Actor.log.info("Shutting down...")
    except Exception as e:
        Actor.log.error(f"Server failed: {e}")
        raise
