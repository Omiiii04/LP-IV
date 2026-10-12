import re
from pathlib import Path


def analyze_log(path: str | Path, keyword: str | None = None, severity: str | None = None) -> dict:
    findings, events = [], []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if keyword and keyword.lower() not in line.lower():
            continue
        if severity and severity.lower() not in line.lower():
            continue
        event = {"line": number, "text": line, "severity": _severity(line)}
        events.append(event)
    failed = [event for event in events if re.search(r"failed\s+login", event["text"], re.I)]
    if len(failed) >= 2:
        findings.append({"reason": "Repeated failed login attempts detected; investigative lead, not proof of malicious activity.", "events": len(failed)})
    return {"events_processed": len(events), "flagged_patterns": len(findings), "events": events, "findings": findings}


def _severity(line: str) -> str:
    for value in ("critical", "error", "warning", "info", "debug"):
        if value in line.lower():
            return value.upper()
    return "UNKNOWN"
