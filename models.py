from datetime import datetime, timezone

from extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    investigator = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(30), default="Open", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    evidence = db.relationship("Evidence", backref="case", lazy=True, cascade="all, delete-orphan")
    disk_images = db.relationship("DiskImage", backref="case", lazy=True, cascade="all, delete-orphan")
    activities = db.relationship("Activity", backref="case", lazy=True, cascade="all, delete-orphan")


class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    description = db.Column(db.String(250), nullable=False)
    source = db.Column(db.Text, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    collected_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    examined_at = db.Column(db.DateTime)
    investigator = db.Column(db.String(120), nullable=False)


class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    action_type = db.Column(db.String(80), nullable=False)
    result = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class LogAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    filename = db.Column(db.String(250), nullable=False)
    events_processed = db.Column(db.Integer, nullable=False)
    flagged_patterns = db.Column(db.Integer, nullable=False)
    findings_json = db.Column(db.Text, nullable=False)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    generated_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class DiskImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=True)
    filename = db.Column(db.String(250), nullable=False)
    source = db.Column(db.Text, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    analysis_status = db.Column(db.String(40), nullable=False)
    results_json = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
