import pytest

from services.file_analyzer import copy_evidence, metadata


def test_metadata_and_safe_evidence_copy(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("proof", encoding="utf-8")
    info = metadata(source)
    destination = tmp_path / "evidence" / "copied.txt"
    copied = copy_evidence(source, destination)
    assert info["sha256"] == copied["sha256"]
    assert destination.read_text(encoding="utf-8") == "proof"


def test_copy_rejects_paths_outside_source_root(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("proof", encoding="utf-8")
    with pytest.raises(ValueError):
        copy_evidence(source, tmp_path / "evidence" / ".." / ".." / "escape.txt")
