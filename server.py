"""
it-ops-mcp-server
=================
An MCP (Model Context Protocol) server that exposes IT operations tools
for AI agents. Enables automated incident triage, log analysis, and
structured incident report generation.

Author: Daniel Vargas Villalobos
GitHub: https://github.com/danvarg91
"""

import json
import re
from datetime import datetime
from typing import Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    # fallback shim for environments without the mcp package installed
    class FastMCP:
        def __init__(self, name): self.name = name; self._tools = {}
        def tool(self):
            def decorator(fn): self._tools[fn.__name__] = fn; return fn
            return decorator
        def run(self): print(f"[{self.name}] {len(self._tools)} tools registered: {list(self._tools)}")

mcp = FastMCP("IT Operations Assistant")

# ── INCIDENT CLASSIFICATION ────────────────────────────────────────────────

INCIDENT_CATEGORIES = {
    "connectivity": ["network", "vpn", "wifi", "internet", "dns", "ping", "timeout", "unreachable", "latency"],
    "authentication": ["login", "password", "locked", "okta", "sso", "saml", "mfa", "access denied", "401", "403"],
    "endpoint": ["laptop", "desktop", "crash", "bsod", "slow", "freeze", "reboot", "driver", "hardware"],
    "cloud": ["aws", "azure", "workspace", "vm", "ec2", "s3", "cloud", "workspaces", "storage"],
    "application": ["app", "software", "install", "update", "error", "crash", "not responding", "license"],
    "email": ["outlook", "email", "calendar", "teams", "sharepoint", "onedrive", "365"],
    "security": ["virus", "malware", "phishing", "suspicious", "alert", "threat", "compliance", "policy"],
}

PRIORITY_SIGNALS = {
    "P1 - Critical": ["c-suite", "executive", "vp ", "ceo", "cto", "cfo", "all users", "production down", "outage"],
    "P2 - High":     ["multiple users", "team", "department", "cannot work", "blocking", "urgent"],
    "P3 - Medium":   ["degraded", "slow", "intermittent", "workaround available"],
    "P4 - Low":      ["single user", "question", "how to", "request", "nice to have"],
}


@mcp.tool()
def classify_incident(description: str) -> str:
    """
    Classify an IT incident based on a description string.
    Returns the most likely category, suggested priority, and recommended
    routing team. Useful for automated ServiceNow queue assignment.

    Args:
        description: Free-text description of the incident or user complaint.

    Returns:
        JSON string with fields: category, priority, routing_team, confidence_note.
    """
    desc_lower = description.lower()

    # Determine category
    category_scores = {}
    for cat, keywords in INCIDENT_CATEGORIES.items():
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score > 0:
            category_scores[cat] = score

    category = max(category_scores, key=category_scores.get) if category_scores else "general"

    # Determine priority
    priority = "P3 - Medium"  # default
    for p, signals in PRIORITY_SIGNALS.items():
        if any(s in desc_lower for s in signals):
            priority = p
            break

    # Routing recommendation
    routing_map = {
        "connectivity":     "Network Operations",
        "authentication":   "Identity & Access Management",
        "endpoint":         "Desktop Support / L2",
        "cloud":            "Cloud Infrastructure",
        "application":      "Application Support",
        "email":            "M365 / Collaboration Support",
        "security":         "Security Operations (SOC)",
        "general":          "L1 Help Desk",
    }

    result = {
        "category":        category,
        "priority":        priority,
        "routing_team":    routing_map.get(category, "L1 Help Desk"),
        "confidence_note": f"Matched {category_scores.get(category, 0)} keyword(s). Review manually if ambiguous.",
        "timestamp":       datetime.utcnow().isoformat() + "Z",
    }
    return json.dumps(result, indent=2)


# ── LOG PARSER ────────────────────────────────────────────────────────────

SEVERITY_LEVELS = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]

LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{4})?)"
    r".*?"
    r"(?P<severity>CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG)"
    r".*?"
    r"(?P<message>.+)$",
    re.IGNORECASE,
)


@mcp.tool()
def parse_log_entries(log_text: str, severity_filter: Optional[str] = None) -> str:
    """
    Parse multi-line system log text and extract structured entries.
    Optionally filter by severity level (CRITICAL, ERROR, WARNING, INFO, DEBUG).

    Args:
        log_text:        Raw log content as a multi-line string.
        severity_filter: Optional severity level to filter by (case-insensitive).
                         If omitted, all parsed entries are returned.

    Returns:
        JSON string with fields: total_lines, parsed_count, filtered_count,
        severity_summary, entries (list of {timestamp, severity, message}).
    """
    lines = log_text.strip().splitlines()
    entries = []
    severity_summary = {s: 0 for s in SEVERITY_LEVELS}

    for line in lines:
        match = LOG_PATTERN.search(line)
        if match:
            sev = match.group("severity").upper()
            if sev == "WARN":
                sev = "WARNING"
            severity_summary[sev] = severity_summary.get(sev, 0) + 1
            entries.append({
                "timestamp": match.group("timestamp"),
                "severity":  sev,
                "message":   match.group("message").strip(),
            })

    # Apply filter
    filtered = entries
    if severity_filter:
        target = severity_filter.upper()
        filtered = [e for e in entries if e["severity"] == target]

    result = {
        "total_lines":    len(lines),
        "parsed_count":   len(entries),
        "filtered_count": len(filtered),
        "severity_summary": severity_summary,
        "entries":          filtered,
    }
    return json.dumps(result, indent=2)


# ── INCIDENT REPORT GENERATOR ─────────────────────────────────────────────

@mcp.tool()
def generate_incident_report(
    title: str,
    description: str,
    affected_systems: str,
    steps_taken: str,
    resolution: Optional[str] = None,
    assignee: Optional[str] = None,
) -> str:
    """
    Generate a structured IT incident report in standard enterprise format.
    Suitable for ServiceNow KBA entries or post-incident review documentation.

    Args:
        title:            Short incident title (e.g. 'VPN connectivity failure - LATAM region').
        description:      Full description of the issue and user impact.
        affected_systems: Comma-separated list of affected systems or services.
        steps_taken:      Troubleshooting steps performed, separated by newlines or semicolons.
        resolution:       Optional — resolution applied (leave empty if still open).
        assignee:         Optional — name or ID of the engineer handling the ticket.

    Returns:
        A formatted plain-text incident report ready for ticket documentation.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    status = "RESOLVED" if resolution else "OPEN / IN PROGRESS"

    steps_formatted = "\n".join(
        f"  {i+1}. {s.strip()}"
        for i, s in enumerate(re.split(r"[\n;]+", steps_taken))
        if s.strip()
    )

    systems_list = "\n".join(f"  - {s.strip()}" for s in affected_systems.split(",") if s.strip())

    report = f"""
╔══════════════════════════════════════════════════════════════════╗
  IT INCIDENT REPORT — {status}
╚══════════════════════════════════════════════════════════════════╝

TITLE          : {title}
GENERATED      : {now}
ASSIGNEE       : {assignee or 'Unassigned'}

──────────────────────────────────────────────────────────────────
DESCRIPTION
──────────────────────────────────────────────────────────────────
{description.strip()}

──────────────────────────────────────────────────────────────────
AFFECTED SYSTEMS / SERVICES
──────────────────────────────────────────────────────────────────
{systems_list}

──────────────────────────────────────────────────────────────────
TROUBLESHOOTING STEPS TAKEN
──────────────────────────────────────────────────────────────────
{steps_formatted}

──────────────────────────────────────────────────────────────────
RESOLUTION
──────────────────────────────────────────────────────────────────
{resolution.strip() if resolution else '[Pending — ticket remains open]'}

══════════════════════════════════════════════════════════════════
  Generated by it-ops-mcp-server | github.com/danvarg91
══════════════════════════════════════════════════════════════════
""".strip()

    return report


# ── SYSTEM HEALTH SUMMARIZER ──────────────────────────────────────────────

@mcp.tool()
def summarize_health_metrics(metrics_json: str) -> str:
    """
    Accepts a JSON object of system health metrics and returns a plain-language
    health summary with flagged anomalies. Useful for agent-driven monitoring workflows.

    Expected input format:
        {
          "hostname": "prod-server-01",
          "cpu_percent": 87.4,
          "memory_percent": 92.1,
          "disk_percent": 55.0,
          "uptime_hours": 342,
          "open_incidents": 3
        }

    Args:
        metrics_json: JSON string containing system metric fields.

    Returns:
        Plain-text health summary with status flags and recommended actions.
    """
    try:
        m = json.loads(metrics_json)
    except json.JSONDecodeError as e:
        return f"Error: Could not parse metrics JSON — {e}"

    hostname = m.get("hostname", "unknown-host")
    cpu      = m.get("cpu_percent", 0)
    mem      = m.get("memory_percent", 0)
    disk     = m.get("disk_percent", 0)
    uptime   = m.get("uptime_hours", 0)
    incidents = m.get("open_incidents", 0)

    flags = []
    if cpu > 85:   flags.append(f"⚠  CPU at {cpu}% — investigate runaway processes")
    if mem > 85:   flags.append(f"⚠  Memory at {mem}% — consider restarting services or adding capacity")
    if disk > 80:  flags.append(f"⚠  Disk at {disk}% — clean up logs or expand storage")
    if uptime > 720: flags.append(f"ℹ  System uptime {uptime}h — schedule maintenance window reboot")
    if incidents > 0: flags.append(f"🔴 {incidents} open incident(s) associated with this host")

    overall = "🟢 HEALTHY" if not flags else ("🔴 CRITICAL" if cpu > 90 or mem > 95 else "🟡 DEGRADED")

    lines = [
        f"Host     : {hostname}",
        f"Status   : {overall}",
        f"CPU      : {cpu}%",
        f"Memory   : {mem}%",
        f"Disk     : {disk}%",
        f"Uptime   : {uptime}h",
        f"Incidents: {incidents} open",
        "",
    ]
    if flags:
        lines += ["Flags:"] + flags
    else:
        lines.append("No anomalies detected.")

    return "\n".join(lines)


# ── ENTRY POINT ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
