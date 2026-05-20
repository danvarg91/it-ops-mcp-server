[it-ops-mcp-server-README.md](https://github.com/user-attachments/files/28056132/it-ops-mcp-server-README.md)
# it-ops-mcp-server# 🤖 it-ops-mcp-server

An **MCP (Model Context Protocol) server** that exposes IT operations tools for AI agents. Built for agent-driven workflows where AI needs to triage incidents, parse system logs, generate documentation, and assess infrastructure health — without human intervention at every step.

---

## 🛠️ Tools Exposed

| Tool | Description |
|------|-------------|
| `classify_incident` | Classifies an IT incident by category, suggests priority, and recommends routing team |
| `parse_log_entries` | Parses raw system log text into structured entries, with optional severity filtering |
| `generate_incident_report` | Generates a structured enterprise-format incident report for ServiceNow or KBA documentation |
| `summarize_health_metrics` | Accepts JSON system metrics and returns a plain-language health summary with flagged anomalies |

---

## 🚀 Quickstart

```bash
# Clone the repo
git clone https://github.com/danvarg91/it-ops-mcp-server
cd it-ops-mcp-server

# Install dependencies
pip install mcp

# Run the server
python server.py
```

---

## 💡 Example Usage

### Classify an incident
```json
{
  "tool": "classify_incident",
  "description": "User cannot connect to VPN, getting timeout errors. Multiple users in the LATAM office affected."
}
```
Returns:
```json
{
  "category": "connectivity",
  "priority": "P2 - High",
  "routing_team": "Network Operations",
  "confidence_note": "Matched 2 keyword(s)."
}
```

### Parse logs and filter by severity
```json
{
  "tool": "parse_log_entries",
  "log_text": "2025-05-01T10:23:11Z ERROR Authentication failed for user jsmith\n2025-05-01T10:24:00Z INFO Session started",
  "severity_filter": "ERROR"
}
```

---

## 🔧 MCP Configuration (Claude Desktop)

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "it-ops": {
      "command": "python",
      "args": ["/path/to/it-ops-mcp-server/server.py"]
    }
  }
}
```

---

## 📌 Context

This project is part of a broader exploration of agentic AI workflows applied to IT operations. The tools here mirror real triage and documentation tasks performed in enterprise L2 support environments — wrapped as MCP tools so AI agents can invoke them autonomously within multi-step workflows.

Related repos:
- [`py-it-automation`](https://github.com/danvarg91/py-it-automation) — Python utilities for IT ops automation
- [`bash-sysadmin-toolkit`](https://github.com/danvarg91/bash-sysadmin-toolkit) — Bash scripts for Linux sysadmin tasks

---

## 👤 Author

**Daniel Vargas Villalobos** — Systems Engineering Student | IT Infrastructure & AI Operations  
📍 San José, Costa Rica | [LinkedIn](https://linkedin.com/in/danvargas91)
