# Architecture

```text
Browser -> Flask routes -> services -> SQLite models
                       |-> instance/storage (outside static)
                       |-> JSON / CSV / PDF report bytes
```

Routes validate request boundaries and delegate hashing, log analysis, evidence copying, image inspection, and report generation to services. The disk-image service is read-only and reports when The Sleuth Kit is unavailable.
