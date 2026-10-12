import json
from uuid import uuid4
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for, jsonify, abort, Response, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename

from config import Config
from extensions import csrf, db
from models import Activity, Case, Evidence, LogAnalysis, Report
from services.file_analyzer import copy_evidence, metadata
from services.hashing import sha256_file
from services.log_analyzer import analyze_log
from services.report_generator import csv_bytes, pdf_bytes, report_data
from services.disk_image_analyzer import examine


class CaseForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    investigator = StringField("Investigator", validators=[DataRequired()])
    description = TextAreaField("Description")


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    Path(app.config["STORAGE_ROOT"]).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    csrf.init_app(app)
    with app.app_context():
        db.create_all()

    def upload_target(folder, original_name):
        suffix = Path(original_name).suffix.lower()
        return Path(app.config["STORAGE_ROOT"]) / folder / f"{uuid4().hex}{suffix}"

    def record_report(case_id):
        db.session.add(Report(case_id=case_id))
        db.session.commit()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html", counts={"cases": Case.query.count(), "evidence": Evidence.query.count(),
            "logs": LogAnalysis.query.count(), "flagged": sum(x.flagged_patterns for x in LogAnalysis.query), "reports": Report.query.count()},
            cases=Case.query.order_by(Case.created_at.desc()).all())

    @app.get("/cases")
    def cases():
        return render_template("cases.html", cases=Case.query.order_by(Case.created_at.desc()).all())

    @app.get("/cases/new")
    def new_case():
        return render_template("case_form.html", form=CaseForm())

    @app.post("/cases")
    def create_case():
        form = CaseForm()
        if not form.validate_on_submit():
            return render_template("case_form.html", form=form), 400
        case = Case(title=form.title.data.strip(), investigator=form.investigator.data.strip(), description=form.description.data or "")
        db.session.add(case)
        db.session.commit()
        flash("Case created.", "success")
        return redirect(url_for("cases"))

    @app.get("/cases/<int:case_id>")
    def case_detail(case_id):
        return render_template("case_detail.html", case=Case.query.get_or_404(case_id))

    @app.post("/cases/<int:case_id>/evidence")
    def add_evidence(case_id):
        case = Case.query.get_or_404(case_id)
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            abort(400, "file is required")
        filename = secure_filename(uploaded.filename)
        if not filename:
            abort(400, "unsafe filename")
        target = upload_target("uploads", filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        uploaded.save(target)
        info = metadata(target)
        db.session.add(Evidence(case_id=case.id, description=filename, source=str(target), sha256=info["sha256"], investigator=case.investigator))
        db.session.add(Activity(case_id=case.id, action_type="evidence_registered", result=filename))
        db.session.commit()
        return redirect(url_for("case_detail", case_id=case.id))

    @app.get("/evidence/<int:evidence_id>/download")
    def download_evidence(evidence_id):
        item = db.session.get(Evidence, evidence_id)
        if item is None or not Path(item.source).is_file():
            abort(404)
        db.session.add(Activity(case_id=item.case_id, action_type="evidence_downloaded", result=item.description))
        db.session.commit()
        return send_file(item.source, as_attachment=True, download_name=item.description)

    @app.post("/cases/<int:case_id>/logs")
    def add_log(case_id):
        case = Case.query.get_or_404(case_id)
        uploaded = request.files.get("file")
        if not uploaded or Path(uploaded.filename or "").suffix.lower() not in {".log", ".txt", ".csv"}:
            abort(400, "only .log, .txt, and .csv files are accepted")
        filename = secure_filename(uploaded.filename)
        target = upload_target("logs", filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        uploaded.save(target)
        result = analyze_log(target)
        db.session.add(LogAnalysis(case_id=case.id, filename=filename, events_processed=result["events_processed"], flagged_patterns=result["flagged_patterns"], findings_json=json.dumps(result)))
        db.session.add(Activity(case_id=case.id, action_type="log_analysis", result=json.dumps(result)))
        db.session.commit()
        return redirect(url_for("case_detail", case_id=case.id))

    @app.get("/reports/<int:case_id>.json")
    def report_json(case_id):
        data = report_data(case_id)
        record_report(case_id)
        return jsonify(data)

    @app.get("/reports/<int:case_id>.csv")
    def report_csv(case_id):
        content = csv_bytes(case_id)
        record_report(case_id)
        return Response(content, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=case-{case_id}.csv"})

    @app.get("/reports/<int:case_id>.pdf")
    def report_pdf(case_id):
        content = pdf_bytes(case_id)
        record_report(case_id)
        return Response(content, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=case-{case_id}.pdf"})

    @app.post("/disk-images")
    def disk_image():
        uploaded = request.files.get("file")
        if not uploaded or Path(uploaded.filename or "").suffix.lower() not in {".dd", ".img"}:
            abort(400, "only .dd and .img files are accepted")
        filename = secure_filename(uploaded.filename)
        target = upload_target("images", filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        uploaded.save(target)
        return jsonify(examine(target))

    @app.errorhandler(404)
    def not_found(error):
        return render_template("404.html"), 404

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
