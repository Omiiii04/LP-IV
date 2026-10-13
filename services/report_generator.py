import csv
import io
import json

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from extensions import db
from models import Activity, Case, DiskImage, Evidence, LogAnalysis


def report_data(case_id: int) -> dict:
    """Aggregates all case records into a unified forensic report dictionary."""
    case = db.session.get(Case, case_id)
    if case is None:
        from flask import abort
        abort(404)

    return {
        "case": {
            "id": case.id,
            "title": case.title,
            "investigator": case.investigator,
            "description": case.description or "",
            "status": case.status,
            "created_at": case.created_at.isoformat(),
        },
        "evidence": [
            {
                "id": e.id,
                "description": e.description,
                "source": e.source,
                "sha256": e.sha256,
                "collected_at": e.collected_at.isoformat() if e.collected_at else "",
                "investigator": e.investigator,
            }
            for e in Evidence.query.filter_by(case_id=case_id).order_by(Evidence.collected_at.asc())
        ],
        "disk_images": [
            {
                "id": i.id,
                "filename": i.filename,
                "sha256": i.sha256,
                "analysis_status": i.analysis_status,
                "results": json.loads(i.results_json) if i.results_json else {},
                "created_at": i.created_at.isoformat() if i.created_at else "",
            }
            for i in DiskImage.query.filter_by(case_id=case_id).order_by(DiskImage.created_at.asc())
        ],
        "logs": [
            {
                "filename": a.filename,
                "events_processed": a.events_processed,
                "flagged_patterns": a.flagged_patterns,
                "findings": json.loads(a.findings_json) if a.findings_json else {},
            }
            for a in LogAnalysis.query.filter_by(case_id=case_id).order_by(LogAnalysis.id.asc())
        ],
        "activities": [
            {
                "action": a.action_type,
                "result": a.result,
                "created_at": a.created_at.isoformat(),
            }
            for a in Activity.query.filter_by(case_id=case_id).order_by(Activity.created_at.asc())
        ],
    }


def csv_bytes(case_id: int) -> bytes:
    """Generates an organized, readable CSV report containing all forensic case artifacts."""
    data = report_data(case_id)
    stream = io.StringIO()
    writer = csv.writer(stream)

    writer.writerow(["section", "field_1", "field_2", "field_3", "field_4"])
    writer.writerow(["case", "ID", data["case"]["id"], "Title", data["case"]["title"]])
    writer.writerow(["case", "Investigator", data["case"]["investigator"], "Status", data["case"]["status"]])
    writer.writerow(["case", "Created", data["case"]["created_at"], "Description", data["case"]["description"]])
    writer.writerow([])

    writer.writerow(["evidence", "ID", "Filename", "SHA-256", "Collected At"])
    for item in data["evidence"]:
        writer.writerow(["evidence", item["id"], item["description"], item["sha256"], item.get("collected_at", "")])
    writer.writerow([])

    writer.writerow(["disk_images", "ID", "Filename", "SHA-256", "Status"])
    for item in data["disk_images"]:
        writer.writerow(["disk_image", item["id"], item["filename"], item["sha256"], item["analysis_status"]])
    writer.writerow([])

    writer.writerow(["log_analyses", "Filename", "Events Processed", "Flagged Patterns", "Summary"])
    for item in data["logs"]:
        findings_count = item.get("flagged_patterns", 0)
        writer.writerow(["log_analysis", item["filename"], item["events_processed"], findings_count, f"{findings_count} pattern(s) flagged"])
    writer.writerow([])

    writer.writerow(["audit_activities", "Action", "Result / Target", "Timestamp"])
    for item in data["activities"]:
        writer.writerow(["activity", item["action"], item["result"], item["created_at"]])

    return stream.getvalue().encode("utf-8")


def _safe_str(text: any, max_len: int = 90) -> str:
    """Sanitizes text to ASCII printable characters for standard ReportLab Helvetica fonts."""
    if text is None:
        return ""
    clean = str(text).encode("ascii", errors="replace").decode("ascii")
    if len(clean) > max_len:
        return clean[:max_len - 3] + "..."
    return clean


def pdf_bytes(case_id: int) -> bytes:
    """
    Generates a professional, multi-page forensic PDF report with pagination,
    headers, footers, sanitized typography, and complete case artifact coverage.
    """
    data = report_data(case_id)
    stream = io.BytesIO()
    doc = canvas.Canvas(stream, pagesize=letter)
    page_num = 1

    def draw_page_decorations(canvas_obj, p_num):
        canvas_obj.setFont("Helvetica-Bold", 8)
        canvas_obj.setFillColorRGB(0.3, 0.4, 0.5)
        canvas_obj.drawString(54, 760, "DIGITAL FORENSICS TOOLKIT · INVESTIGATIVE REPORT")
        canvas_obj.setStrokeColorRGB(0.8, 0.85, 0.9)
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(54, 752, 558, 752)

        # Footer
        canvas_obj.line(54, 45, 558, 45)
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.drawString(54, 32, "Confidential Forensic Work Product · Application-level audit record")
        canvas_obj.drawRightString(558, 32, f"Page {p_num}")

    draw_page_decorations(doc, page_num)
    y = 725

    def ensure_space(needed=20):
        nonlocal y, page_num
        if y - needed < 55:
            doc.showPage()
            page_num += 1
            draw_page_decorations(doc, page_num)
            y = 725

    # Case Header
    doc.setFont("Helvetica-Bold", 16)
    doc.setFillColorRGB(0.05, 0.1, 0.2)
    doc.drawString(54, y, _safe_str(f"Case #{data['case']['id']}: {data['case']['title']}"))
    y -= 22

    doc.setFont("Helvetica", 9)
    doc.setFillColorRGB(0.2, 0.25, 0.3)
    doc.drawString(54, y, _safe_str(f"Investigator: {data['case']['investigator']}  |  Status: {data['case']['status']}  |  Opened: {data['case']['created_at'][:10]}"))
    y -= 16

    if data["case"]["description"]:
        doc.setFont("Helvetica-Oblique", 8.5)
        doc.setFillColorRGB(0.35, 0.4, 0.45)
        doc.drawString(54, y, _safe_str(f"Scope: {data['case']['description']}", 95))
        y -= 20
    else:
        y -= 10

    # Section 1: Registered Evidence Items
    ensure_space(35)
    doc.setFont("Helvetica-Bold", 11)
    doc.setFillColorRGB(0.05, 0.3, 0.4)
    doc.drawString(54, y, f"1. Evidence Inventory ({len(data['evidence'])} item(s))")
    y -= 15

    if not data["evidence"]:
        doc.setFont("Helvetica-Oblique", 8.5)
        doc.setFillColorRGB(0.4, 0.4, 0.4)
        doc.drawString(64, y, "No evidence files registered.")
        y -= 16
    else:
        for idx, item in enumerate(data["evidence"], 1):
            ensure_space(24)
            doc.setFont("Helvetica-Bold", 8.5)
            doc.setFillColorRGB(0.1, 0.15, 0.2)
            doc.drawString(64, y, _safe_str(f"[{idx}] {item['description']}"))
            y -= 11

            doc.setFont("Courier", 7.5)
            doc.setFillColorRGB(0.25, 0.3, 0.35)
            doc.drawString(74, y, f"SHA-256: {item['sha256']}")
            y -= 13

    # Section 2: Disk Images
    y -= 8
    ensure_space(35)
    doc.setFont("Helvetica-Bold", 11)
    doc.setFillColorRGB(0.05, 0.3, 0.4)
    doc.drawString(54, y, f"2. Disk Images ({len(data['disk_images'])} item(s))")
    y -= 15

    if not data["disk_images"]:
        doc.setFont("Helvetica-Oblique", 8.5)
        doc.setFillColorRGB(0.4, 0.4, 0.4)
        doc.drawString(64, y, "No raw disk images registered.")
        y -= 16
    else:
        for idx, img in enumerate(data["disk_images"], 1):
            ensure_space(24)
            doc.setFont("Helvetica-Bold", 8.5)
            doc.setFillColorRGB(0.1, 0.15, 0.2)
            doc.drawString(64, y, _safe_str(f"[{idx}] {img['filename']} ({img['analysis_status']})"))
            y -= 11

            doc.setFont("Courier", 7.5)
            doc.setFillColorRGB(0.25, 0.3, 0.35)
            doc.drawString(74, y, f"SHA-256: {img['sha256']}")
            y -= 13

    # Section 3: Log Analyses & Findings
    y -= 8
    ensure_space(35)
    doc.setFont("Helvetica-Bold", 11)
    doc.setFillColorRGB(0.05, 0.3, 0.4)
    doc.drawString(54, y, f"3. Log Analyses & Investigative Leads ({len(data['logs'])} log(s))")
    y -= 15

    if not data["logs"]:
        doc.setFont("Helvetica-Oblique", 8.5)
        doc.setFillColorRGB(0.4, 0.4, 0.4)
        doc.drawString(64, y, "No log files analyzed.")
        y -= 16
    else:
        for idx, log_item in enumerate(data["logs"], 1):
            ensure_space(24)
            doc.setFont("Helvetica-Bold", 8.5)
            doc.setFillColorRGB(0.1, 0.15, 0.2)
            doc.drawString(64, y, _safe_str(f"[{idx}] {log_item['filename']} - {log_item['events_processed']} events, {log_item['flagged_patterns']} flagged"))
            y -= 12

            findings = log_item.get("findings", {}).get("findings", [])
            for finding in findings:
                ensure_space(14)
                doc.setFont("Helvetica", 8)
                doc.setFillColorRGB(0.6, 0.2, 0.0)
                doc.drawString(74, y, _safe_str(f"• Lead: {finding.get('reason', '')}"))
                y -= 11

    # Section 4: Chain of Custody / Activity Trail
    y -= 8
    ensure_space(35)
    doc.setFont("Helvetica-Bold", 11)
    doc.setFillColorRGB(0.05, 0.3, 0.4)
    doc.drawString(54, y, f"4. Chain of Custody & Activity Log ({len(data['activities'])} action(s))")
    y -= 15

    if not data["activities"]:
        doc.setFont("Helvetica-Oblique", 8.5)
        doc.setFillColorRGB(0.4, 0.4, 0.4)
        doc.drawString(64, y, "No recorded custody activities.")
    else:
        for act in data["activities"]:
            ensure_space(14)
            doc.setFont("Helvetica", 7.5)
            doc.setFillColorRGB(0.2, 0.2, 0.2)
            time_str = act["created_at"][:19].replace("T", " ")
            action_str = act["action"].replace("_", " ").title()
            doc.drawString(64, y, _safe_str(f"{time_str} - {action_str}: {act['result']}", 95))
            y -= 11

    doc.save()
    return stream.getvalue()
