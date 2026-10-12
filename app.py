import json
from uuid import uuid4
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for, jsonify, abort, Response, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException

from config import Config
from extensions import csrf, db
from models import Activity, Case, Evidence, LogAnalysis, Report, DiskImage
from services.file_analyzer import copy_evidence, metadata
from services.hashing import sha256_file, hashes_match
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
        root = Path(app.config["STORAGE_ROOT"]).resolve()
        target = (root / folder / f"{uuid4().hex}{suffix}").resolve()
        target.relative_to(root)
        return target

    def save_upload(uploaded, folder, allowed):
        filename = secure_filename(uploaded.filename or "")
        if not filename or Path(filename).suffix.lower() not in allowed:
            abort(400, "invalid or unsupported file type")
        target = upload_target(folder, filename)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            uploaded.save(target)
            if target.stat().st_size == 0:
                raise ValueError("empty uploads are not accepted")
            return filename, target
        except Exception:
            target.unlink(missing_ok=True)
            raise

    def record_report(case_id):
        db.session.add(Report(case_id=case_id))
        db.session.commit()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def dashboard():
        recent_activity = Activity.query.order_by(Activity.created_at.desc()).limit(8).all()
        return render_template("dashboard.html", counts={"cases": Case.query.count(), "evidence": Evidence.query.count(),
            "logs": LogAnalysis.query.count(), "flagged": sum(x.flagged_patterns for x in LogAnalysis.query), "reports": Report.query.count()},
            cases=Case.query.order_by(Case.created_at.desc()).limit(5).all(), recent_activity=recent_activity)

    @app.get("/cases")
    def cases():
        return render_template("cases.html", cases=Case.query.order_by(Case.created_at.desc()).all())

    @app.get("/evidence")
    def evidence_index():
        items = Evidence.query.order_by(Evidence.collected_at.desc()).all()
        statuses = {}
        for item in items:
            statuses[item.id] = "Integrity failure" if Activity.query.filter_by(case_id=item.case_id, action_type="evidence_integrity_failure", result=item.description).first() else (
                "Verified on download" if Activity.query.filter_by(case_id=item.case_id, action_type="evidence_downloaded", result=item.description).first() else "Not yet verified")
        return render_template("evidence.html", items=items, statuses=statuses)

    @app.get("/logs")
    def logs_index():
        return render_template("logs.html", analyses=LogAnalysis.query.order_by(LogAnalysis.id.desc()).all())

    @app.get("/disk-images")
    def disk_images_index():
        return render_template("disk_images.html", images=DiskImage.query.order_by(DiskImage.created_at.desc()).all(), cases=Case.query.order_by(Case.title).all())

    @app.get("/reports")
    def reports_index():
        return render_template("reports.html", cases=Case.query.order_by(Case.title).all())

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
        db.session.add(Activity(case_id=case.id, action_type="case_created", result=case.title))
        db.session.commit()
        flash("Case created.", "success")
        return redirect(url_for("cases"))

    @app.get("/cases/<int:case_id>")
    def case_detail(case_id):
        case = Case.query.get_or_404(case_id)
        analyses = LogAnalysis.query.filter_by(case_id=case.id).order_by(LogAnalysis.id.desc()).all()
        for analysis in analyses:
            analysis.findings = json.loads(analysis.findings_json)
        reports = Report.query.filter_by(case_id=case.id).order_by(Report.generated_at.desc()).all()
        activities = Activity.query.filter_by(case_id=case.id).order_by(Activity.created_at.desc()).all()
        return render_template("case_detail.html", case=case, analyses=analyses, reports=reports, activities=activities)

    @app.post("/cases/<int:case_id>/evidence")
    def add_evidence(case_id):
        case = Case.query.get_or_404(case_id)
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            abort(400, "file is required")
        try:
            filename, target = save_upload(uploaded, "uploads", app.config["ALLOWED_EVIDENCE_EXTENSIONS"])
            info = metadata(target)
            db.session.add(Evidence(case_id=case.id, description=filename, source=str(target), sha256=info["sha256"], investigator=case.investigator))
            db.session.add(Activity(case_id=case.id, action_type="evidence_registered", result=filename))
            db.session.commit()
            flash(f"Evidence registered: {filename}", "success")
        except ValueError as error:
            db.session.rollback()
            abort(400, str(error))
        except HTTPException:
            db.session.rollback()
            raise
        except Exception:
            db.session.rollback()
            if "target" in locals():
                target.unlink(missing_ok=True)
            abort(500, "evidence registration failed")
        return redirect(url_for("case_detail", case_id=case.id))

    @app.get("/evidence/<int:evidence_id>/download")
    def download_evidence(evidence_id):
        item = db.session.get(Evidence, evidence_id)
        if item is None or not Path(item.source).is_file():
            abort(404)
        if not hashes_match(item.source, item.sha256):
            db.session.add(Activity(case_id=item.case_id, action_type="evidence_integrity_failure", result=item.description))
            db.session.commit()
            abort(409, "evidence integrity verification failed")
        db.session.add(Activity(case_id=item.case_id, action_type="evidence_downloaded", result=item.description))
        db.session.commit()
        return send_file(item.source, as_attachment=True, download_name=item.description)

    @app.post("/cases/<int:case_id>/logs")
    def add_log(case_id):
        case = Case.query.get_or_404(case_id)
        uploaded = request.files.get("file")
        if not uploaded:
            abort(400, "file is required")
        try:
            filename, target = save_upload(uploaded, "logs", app.config["ALLOWED_LOG_EXTENSIONS"])
        except ValueError as error:
            abort(400, str(error))
        result = analyze_log(target)
        db.session.add(LogAnalysis(case_id=case.id, filename=filename, events_processed=result["events_processed"], flagged_patterns=result["flagged_patterns"], findings_json=json.dumps(result)))
        db.session.add(Activity(case_id=case.id, action_type="log_analysis", result=json.dumps(result)))
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            target.unlink(missing_ok=True)
            abort(500, "log registration failed")
        flash(f"Log analyzed: {filename}", "success")
        return redirect(url_for("case_detail", case_id=case.id))

    @app.get("/reports/<int:case_id>.json")
    def report_json(case_id):
        try:
            data = report_data(case_id)
        except HTTPException:
            raise
        except Exception:
            abort(500, "report generation failed")
        record_report(case_id)
        return jsonify(data)

    @app.get("/reports/<int:case_id>.csv")
    def report_csv(case_id):
        try:
            content = csv_bytes(case_id)
        except HTTPException:
            raise
        except Exception:
            abort(500, "report generation failed")
        record_report(case_id)
        return Response(content, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=case-{case_id}.csv"})

    @app.get("/reports/<int:case_id>.pdf")
    def report_pdf(case_id):
        try:
            content = pdf_bytes(case_id)
        except HTTPException:
            raise
        except Exception:
            abort(500, "report generation failed")
        record_report(case_id)
        return Response(content, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=case-{case_id}.pdf"})

    @app.post("/disk-images")
    def disk_image():
        uploaded = request.files.get("file")
        if not uploaded:
            abort(400, "file is required")
        case_id = request.form.get("case_id", type=int)
        if case_id is None or db.session.get(Case, case_id) is None:
            abort(400, "a valid case is required")
        filename, target = save_upload(uploaded, "images", app.config["ALLOWED_DISK_IMAGE_EXTENSIONS"])
        try:
            result = examine(target)
            item = DiskImage(case_id=case_id, filename=filename, source=str(target),
                             sha256=result["sha256_before"], analysis_status="hash_only", results_json=json.dumps(result))
            db.session.add(item)
            db.session.add(Activity(case_id=case_id, action_type="disk_image_registered", result=filename))
            db.session.commit()
            return jsonify({**result, "id": item.id, "sha256": item.sha256, "analysis_status": item.analysis_status})
        except Exception:
            db.session.rollback()
            target.unlink(missing_ok=True)
            abort(500, "disk-image registration failed")

    @app.errorhandler(404)
    def not_found(error):
        return render_template("404.html"), 404

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
