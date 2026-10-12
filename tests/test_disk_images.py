import pytest

from services.disk_image_analyzer import examine


def test_disk_image_hashes_supported_read_only_image(tmp_path):
    image = tmp_path / "image.dd"
    image.write_bytes(b"synthetic image")
    result = examine(image)
    assert result["read_only"] is True
    assert len(result["sha256_before"]) == 64


def test_disk_image_rejects_unsupported_format(tmp_path):
    image = tmp_path / "image.bin"
    image.write_bytes(b"not an image")
    with pytest.raises(ValueError, match="unsupported"):
        examine(image)


def test_disk_image_metadata_is_persisted(client, app):
    import io
    import re
    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(1)
    client.post("/cases", data={"title": "Image review", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from models import Case
        case_id = Case.query.one().id
    response = client.post("/disk-images", data={"case_id": str(case_id), "file": (io.BytesIO(b"synthetic image"), "image.dd"), "csrf_token": token}, content_type="multipart/form-data")
    assert response.status_code == 200
    with app.app_context():
        from models import DiskImage
        item = DiskImage.query.one()
        assert item.sha256 == response.json["sha256_before"]
        assert item.analysis_status == "hash_only"
