import os
from pathlib import Path


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///dft.sqlite3")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    STORAGE_ROOT = os.getenv("STORAGE_ROOT", str(Path("instance") / "storage"))
    ALLOWED_EVIDENCE_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".pdf", ".zip", ".doc", ".docx", ".dd", ".img"}
    ALLOWED_LOG_EXTENSIONS = {".log", ".txt", ".csv"}
    ALLOWED_DISK_IMAGE_EXTENSIONS = {".dd", ".img"}

