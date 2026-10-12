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
