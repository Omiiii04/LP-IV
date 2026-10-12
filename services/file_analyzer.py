import shutil
from pathlib import Path

from .hashing import sha256_file


def metadata(path: str | Path) -> dict:
    path = Path(path)
    stat = path.stat()
    return {"name": path.name, "extension": path.suffix.lower(), "size": stat.st_size,
            "modified": stat.st_mtime, "sha256": sha256_file(path)}


def copy_evidence(source: str | Path, destination: str | Path) -> dict:
    source, destination = Path(source).resolve(), Path(destination).resolve()
    try:
        destination.relative_to(source.parent)
    except ValueError:
        raise ValueError("destination must remain inside the authorized evidence root")
    if not source.is_file() or destination == source:
        raise ValueError("source must be a file and destination must differ")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValueError("refusing to overwrite evidence")
    shutil.copy2(source, destination)
    result = metadata(destination)
    if result["sha256"] != sha256_file(source):
        destination.unlink(missing_ok=True)
        raise ValueError("hash mismatch after copy")
    return result
