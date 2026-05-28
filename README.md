# GitHub Actions Security Audit

> MCP server that audits `.github/workflows/*.yml` files for supply-chain risks. Catches script injection, leaked tokens, unpinned actions, broad permissions, and `pull_request_target` foot-guns — the patterns behind several 2024–2025 supply-chain incidents.

**Built by [Unbearable Labs](https://github.com/UnbearableDev).** Pay-per-event — only billed when a tool is actually called.

---

## Available on

- [Apify Actor Store](https://apify.com/unbearable_dev/github-actions-audit) — primary, metered usage (PPE)
- MCPize — *pending submission*
- MCP.so — *pending submission*
- PulseMCP — *pending submission*
- Smithery — *pending submission*
- Glama — *pending submission*

**Newsletter:** [Unbearable TechTips Weekly](https://unbearabletechtips.com) · **All Actors:** [github.com/UnbearableDev](https://github.com/UnbearableDev)

## What it does

Point any MCP-capable client (Claude Desktop, Cursor, n8n, Make, Zapier, custom agents) at this server, hand it a workflow YAML, and get back structured findings with:

- **Severity** — critical / high / medium / low / info
- **Affected job and step** — exact location of the problem
- **Description** — why it matters, with the actual attack vector
- **Remediation** — what to do about it
- **Fix snippet** — YAML you can paste directly

## Tools

| Tool | Purpose |
|------|---------|
| `audit_workflow(workflow_yaml? \| workflow_url?, min_severity='low')` | Run all checks |
| `check_secrets(...)` | Secret-leakage paths only |
| `check_permissions(...)` | `GITHUB_TOKEN` scope issues only |
| `check_action_pinning(...)` | Action version-pinning only |
| `check_runner_security(...)` | Self-hosted runner + script injection |
| `check_workflow_config(...)` | Timeout / config hygiene |
| `check_supply_chain_advanced(...)` | TeamPCP-class supply-chain patterns (GHA-201..208) |
| `list_checks(category?)` | Browse the catalog |

Provide exactly one of `workflow_yaml` (paste the content) or `workflow_url` (HTTPS URL — typically a GitHub raw URL to a specific workflow file).

## Check catalog (v2: 21 checks)

| ID | Category | Severity | Title |
|----|----------|----------|-------|
| GHA-001 | secrets | high | Secret interpolated directly into `run:` script |
| GHA-002 | secrets | high | Secret printed via echo / set-output |
| GHA-003 | secrets | medium | Secret used in `if:` condition |
| GHA-004 | secrets | high | Hardcoded credential pattern in `env:` |
| GHA-010 | permissions | high | `permissions: write-all` granted |
| GHA-011 | permissions | medium | No top-level `permissions:` (inherits broad default) |
| GHA-013 | permissions | high | `pull_request_target` + checkout PR head = PWNing pattern |
| GHA-020 | action_pinning | high | Third-party action pinned to mutable tag |
| GHA-021 | action_pinning | high | Third-party action pinned to mutable branch |
| GHA-022 | action_pinning | medium | First-party action not SHA-pinned |
| GHA-030 | runner_security | medium | Self-hosted runner used on `pull_request` from forks |
| GHA-032 | runner_security | high | Script injection via untrusted `github.event.*` interpolation |
| GHA-040 | workflow_config | low | No `timeout-minutes` on job |
| GHA-201 | supply_chain_advanced | high | Action pinned to unpinned branch ref (TeamPCP-class: @main/@master) |
| GHA-202 | supply_chain_advanced | high | Action pinned to mutable tag — SHA pin recommended |
| GHA-203 | supply_chain_advanced | critical | `pull_request_target` + checkout of PR head SHA/ref (codecov/tj-actions exploitation path) |
| GHA-204 | supply_chain_advanced | high | Script injection via `github.event.*` user-controlled field in `run:` |
| GHA-205 | supply_chain_advanced | medium | Action from non-allowlisted owner (untrusted 3rd-party) |
| GHA-206 | supply_chain_advanced | high | Top-level `permissions: write-all` or `contents: write` without per-job scoping |
| GHA-207 | supply_chain_advanced | medium | Secret logged via `echo` / `cat` in `run:` block |
| GHA-208 | supply_chain_advanced | low | Action uses a known-retired tag |

## Pricing

| Event | USD |
|-------|-----|
| Any audit / check_* tool call | $0.02 |
| `list_checks` discovery | $0.005 |

## Connecting from Claude Desktop

```json
{
  "mcpServers": {
    "gha-audit": {
      "transport": "streamable-http",
      "url": "https://YOUR-ACTOR-URL.apify.actor/mcp"
    }
  }
}
```

## Sibling MCPs from Unbearable Labs

- **[`docker-compose-audit`](https://apify.com/unbearable_dev/docker-compose-audit)** — `docker-compose.yml` security audit
- **[`dockerfile-audit`](https://apify.com/unbearable_dev/dockerfile-audit)** — Dockerfile security & quality
- **[`hu-postcode-validator`](https://apify.com/unbearable_dev/hu-postcode-validator)** — Hungarian postcode lookup

## What's NOT covered (yet)

- Reusable workflow auditing (multi-file resolution)
- CodeQL-grade dataflow tracking
- Marketplace-listed action reputation scoring

## Source / contact

Source: [github.com/UnbearableDev/github-actions-audit](https://github.com/UnbearableDev/github-actions-audit).
Issues + ideas: `unbearabledev@gmail.com`.
