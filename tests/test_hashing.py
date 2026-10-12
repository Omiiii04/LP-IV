from services.hashing import sha256_file, hashes_match


def test_sha256_and_mismatch_detection(tmp_path):
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"forensic evidence")
    digest = sha256_file(path)
    assert len(digest) == 64
    assert hashes_match(path, digest)
    assert not hashes_match(path, "0" * 64)
