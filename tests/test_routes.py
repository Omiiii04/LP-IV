def test_health_and_csrf(client):
    assert client.get("/health").json == {"status": "ok"}
    response = client.post("/cases", data={"title": "case"})
    assert response.status_code == 400


def test_case_creation_and_dashboard(client):
    token = client.get("/cases/new").data.decode()
    import re
    csrf = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', token).group(1)
    response = client.post("/cases", data={"title": "Laptop review", "investigator": "Analyst", "csrf_token": csrf})
    assert response.status_code == 302
    assert b"Laptop review" in client.get("/cases").data
    assert b"Laptop review" in client.get("/").data


def test_evidence_uploads_use_unique_storage_names_and_preserve_original(client, app):
    import io
    import re
    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(1)
    client.post("/cases", data={"title": "Incident", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from models import Case
        case_id = Case.query.one().id
    for content in (b"one", b"two"):
        response = client.post(f"/cases/{case_id}/evidence", data={"file": (io.BytesIO(content), "same.txt"), "csrf_token": token}, content_type="multipart/form-data")
        assert response.status_code == 302
    with app.app_context():
        from models import Evidence
        items = Evidence.query.order_by(Evidence.id).all()
        assert [item.description for item in items] == ["same.txt", "same.txt"]
        assert len({item.source for item in items}) == 2


def test_evidence_download_uses_registered_record(client, app):
    import io
    import re
    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(1)
    client.post("/cases", data={"title": "Incident", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from models import Case
        case_id = Case.query.one().id
    client.post(f"/cases/{case_id}/evidence", data={"file": (io.BytesIO(b"proof"), "proof.txt"), "csrf_token": token}, content_type="multipart/form-data")
    with app.app_context():
        from models import Evidence
        evidence_id = Evidence.query.one().id
    response = client.get(f"/evidence/{evidence_id}/download")
    assert response.status_code == 200
    assert response.data == b"proof"
    assert "proof.txt" in response.headers["Content-Disposition"]
    assert client.get("/evidence/999/download").status_code == 404
