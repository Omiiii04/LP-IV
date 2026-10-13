import hashlib
from pathlib import Path


def multi_hash_file(path: str | Path) -> dict:
    """Calculates MD5, SHA-1, and SHA-256 digests in a single streaming pass."""
    md5_digest = hashlib.md5()
    sha1_digest = hashlib.sha1()
    sha256_digest = hashlib.sha256()

    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            md5_digest.update(chunk)
            sha1_digest.update(chunk)
            sha256_digest.update(chunk)

    return {
        "md5": md5_digest.hexdigest(),
        "sha1": sha1_digest.hexdigest(),
        "sha256": sha256_digest.hexdigest(),
    }


def sha256_file(path: str | Path) -> str:
    """Calculates the SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hashes_match(path: str | Path, expected: str) -> bool:
    """Verifies whether the file's SHA-256 digest matches the expected hash."""
    return sha256_file(path).lower() == expected.lower().strip()
