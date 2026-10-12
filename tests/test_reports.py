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
