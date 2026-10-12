import csv
import io
import json

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from extensions import db
from models import Activity, Case, Evidence, LogAnalysis, DiskImage


def report_data(case_id: int) -> dict:
    case = db.session.get(Case, case_id)
    if case is None:
        from flask import abort
        abort(404)
    return {"case": {"id": case.id, "title": case.title, "investigator": case.investigator,
                      "description": case.description, "status": case.status, "created_at": case.created_at.isoformat()},
            "evidence": [{"id": e.id, "description": e.description, "source": e.source, "sha256": e.sha256} for e in Evidence.query.filter_by(case_id=case_id)],
            "disk_images": [{"id": i.id, "filename": i.filename, "sha256": i.sha256, "analysis_status": i.analysis_status,
                             "results": json.loads(i.results_json)} for i in DiskImage.query.filter_by(case_id=case_id)],
            "logs": [json.loads(a.findings_json) for a in LogAnalysis.query.filter_by(case_id=case_id)],
            "activities": [{"action": a.action_type, "result": a.result, "created_at": a.created_at.isoformat()} for a in Activity.query.filter_by(case_id=case_id)]}


def csv_bytes(case_id: int) -> bytes:
    data = report_data(case_id)
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["section", "value"])
    writer.writerow(["case", json.dumps(data["case"])])
    for item in data["evidence"]:
        writer.writerow(["evidence", json.dumps(item)])
    for item in data["disk_images"]:
        writer.writerow(["disk_image", json.dumps(item)])
    for item in data["activities"]:
        writer.writerow(["activity", json.dumps(item)])
    return stream.getvalue().encode("utf-8")


def pdf_bytes(case_id: int) -> bytes:
    data = report_data(case_id)
    stream = io.BytesIO()
    document = canvas.Canvas(stream, pagesize=letter)
    document.drawString(72, 740, f"DFT Report: {data['case']['title']}")
    document.drawString(72, 720, f"Investigator: {data['case']['investigator']}")
    document.drawString(72, 700, f"Evidence items: {len(data['evidence'])}")
    document.drawString(72, 680, f"Generated: {data['case']['created_at']}")
    y = 660
    for item in data["evidence"]:
        document.drawString(72, y, f"Evidence {item['description']}: {item['sha256']}")
        y -= 15
    for item in data["disk_images"]:
        document.drawString(72, y, f"Image {item['filename']}: {item['sha256']} ({item['analysis_status']})")
        y -= 15
    document.save()
    return stream.getvalue()
