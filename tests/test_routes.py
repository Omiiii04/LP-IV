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
