from pathlib import Path
from .hashing import sha256_file


def examine(path: str | Path) -> dict:
    path = Path(path)
    if path.suffix.lower() not in {".dd", ".img"}:
        raise ValueError("unsupported disk-image format; use .dd or .img")
    return {"path": path.name, "sha256_before": sha256_file(path), "read_only": True,
            "message": "The Sleuth Kit integration is unavailable; image hash was verified only."}
