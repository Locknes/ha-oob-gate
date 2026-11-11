# Claude Code Instructions (`ha-oob-gate`)

See [`AGENTS.md`](AGENTS.md) and [`skills/oob-auth/SKILL.md`](skills/oob-auth/SKILL.md) for using and developing `ha-oob-gate`.

- **MCP Server:** Run `oob-auth --mcp-stdio` to expose all 8 OOB elevation tools (`oob_sudo_batch`, `oob_k8s_token`, `oob_github_token`, `oob_ha_api`, `oob_ha_api_call`, `oob_secret_checkout`, `oob_confirm`, `oob_revoke`) over JSON-RPC 2.0 stdio.
- **Test Suite:** Run `python3 -m unittest discover -s tests -v` (Python 3.10+, zero external dependencies required).
