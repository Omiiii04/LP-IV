def test_report_json_contains_case_data(app, client):
    with app.app_context():
        from models import Case
        from extensions import db
        case = Case(title="Incident", investigator="Analyst")
        db.session.add(case)
        db.session.commit()
        case_id = case.id
    response = client.get(f"/reports/{case_id}.json")
    assert response.status_code == 200
    assert response.json["case"]["title"] == "Incident"


def test_report_csv_and_pdf_downloads(app, client):
    with app.app_context():
        from models import Case
        from extensions import db
        case = Case(title="Incident", investigator="Analyst")
        db.session.add(case)
        db.session.commit()
        case_id = case.id
    assert client.get(f"/reports/{case_id}.csv").mimetype == "text/csv"
    assert client.get(f"/reports/{case_id}.pdf").mimetype == "application/pdf"


def test_every_report_format_creates_a_report_record(app, client):
    with app.app_context():
        from models import Case, Report
        from extensions import db
        case = Case(title="Incident", investigator="Analyst")
        db.session.add(case)
        db.session.commit()
        case_id = case.id
    for extension in ("json", "csv", "pdf"):
        assert client.get(f"/reports/{case_id}.{extension}").status_code == 200
    with app.app_context():
        from models import Report
        assert Report.query.filter_by(case_id=case_id).count() == 3
