# Digital Forensics Toolkit

Local, single-user academic Flask prototype for hash verification, case/evidence registration, safe uploads, log analysis, and JSON reports. Audit records are application-level and are not independently tamper-proof. Findings are investigative leads, not proof of malicious activity.

## Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Set `SECRET_KEY` and `STORAGE_ROOT` in the environment for real use. Tests run with `pytest -q`.

Uploads are stored under `STORAGE_ROOT` with UUID names. Evidence extensions are configured by `ALLOWED_EVIDENCE_EXTENSIONS`; log and disk-image formats use `ALLOWED_LOG_EXTENSIONS` and `ALLOWED_DISK_IMAGE_EXTENSIONS`. Flask's `MAX_CONTENT_LENGTH` limits upload size. Evidence downloads recalculate and verify the recorded SHA-256 before serving; a mismatch is logged and rejected. Disk-image analysis currently persists metadata and a hash-only status; The Sleuth Kit partition/filesystem analysis is not implemented.
