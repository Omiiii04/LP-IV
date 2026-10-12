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
