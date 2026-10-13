import re
from pathlib import Path


SEVERITY_PATTERNS = [
    (re.compile(r"\b(CRITICAL|FATAL|EMERG|ALERT)\b", re.IGNORECASE), "CRITICAL"),
    (re.compile(r"\b(ERROR|ERR)\b", re.IGNORECASE), "ERROR"),
    (re.compile(r"\b(WARN|WARNING)\b", re.IGNORECASE), "WARNING"),
    (re.compile(r"\b(INFO|NOTICE)\b", re.IGNORECASE), "INFO"),
    (re.compile(r"\b(DEBUG|TRACE)\b", re.IGNORECASE), "DEBUG"),
]


def _detect_severity(line: str) -> str:
    """Accurately identifies severity level using word boundaries to prevent substring collisions."""
    for pattern, name in SEVERITY_PATTERNS:
        if pattern.search(line):
            return name
    return "UNKNOWN"


def analyze_log(path: str | Path, keyword: str | None = None, severity: str | None = None) -> dict:
    """
    Parses and analyzes a forensic log file, extracting events and flagging investigative security leads.
    """
    findings = []
    events = []
    severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0, "DEBUG": 0, "UNKNOWN": 0}

    path_obj = Path(path)
    if not path_obj.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    # Process line by line with robust encoding fallback
    try:
        content = path_obj.read_text(encoding="utf-8", errors="replace")
    except Exception:
        content = path_obj.read_bytes().decode("latin-1", errors="replace")

    all_lines = content.splitlines()

    for number, line in enumerate(all_lines, 1):
        line_sev = _detect_severity(line)
        severity_counts[line_sev] = severity_counts.get(line_sev, 0) + 1

        if keyword and keyword.lower() not in line.lower():
            continue
        if severity and severity.upper() != "ALL" and severity.upper() != line_sev:
            continue

        events.append({
            "line": number,
            "text": line,
            "severity": line_sev,
        })

    # 1. Repeated failed logins check (Case-insensitive)
    failed = [e for e in events if re.search(r"failed\s+login|authentication\s+failure|invalid\s+password", e["text"], re.I)]
    if len(failed) >= 2:
        findings.append({
            "reason": "Repeated failed login attempts detected; investigative lead, not proof of malicious activity.",
            "events": len(failed),
            "severity": "WARNING",
        })

    # 2. Path traversal check
    traversals = [e for e in events if re.search(r"(?:\.\./|\.\.\\|%2e%2e)", e["text"], re.I)]
    if len(traversals) >= 1:
        findings.append({
            "reason": "Directory traversal sequence (e.g., ../) detected in log text.",
            "events": len(traversals),
            "severity": "WARNING",
        })

    # 3. Privilege escalation or sensitive command patterns
    priv_escalation = [e for e in events if re.search(r"\b(sudo\s+su|chmod\s+777|/etc/shadow|whoami\s+/priv)\b", e["text"], re.I)]
    if len(priv_escalation) >= 1:
        findings.append({
            "reason": "Privilege escalation or sensitive credential access pattern detected.",
            "events": len(priv_escalation),
            "severity": "CRITICAL",
        })

    # 4. Potential SQL Injection pattern
    sqli = [e for e in events if re.search(r"(?:UNION\s+SELECT|OR\s+['\"]?1['\"]?\s*=\s*['\"]?1|WAITFOR\s+DELAY|;\s*DROP\s+TABLE)", e["text"], re.I)]
    if len(sqli) >= 1:
        findings.append({
            "reason": "Suspicious SQL syntax or boolean-based injection attempt detected.",
            "events": len(sqli),
            "severity": "CRITICAL",
        })

    return {
        "events_processed": len(events),
        "total_lines": len(all_lines),
        "flagged_patterns": len(findings),
        "severity_counts": severity_counts,
        "events": events,
        "findings": findings,
    }
