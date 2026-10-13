import io
import json
import re
import struct
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app import create_app
from extensions import db
from models import Case, Evidence, Activity, LogAnalysis, DiskImage, Report
from services.hashing import multi_hash_file, hashes_match
from services.disk_image_analyzer import examine
from services.log_analyzer import analyze_log
from services.report_generator import report_data, csv_bytes, pdf_bytes


def run_simulation():
    app = create_app()
    client = app.test_client()

    print("=" * 70)
    print("DIGITAL FORENSICS TOOLKIT · AUTOMATED SIMULATION & AUDIT")
    print("=" * 70)

    # 1. CREATE CASE
    print("\n[STEP 1] Initializing Forensic Case...")
    case_title = "Operation Chimera - Corporate Data Exfiltration"
    investigator = "Senior Forensic Lead Dr. Elena Rostova"
    description = (
        "Investigation into unauthorized access, web shell deployment, "
        "and exfiltration of proprietary engineering schematics from internal server."
    )

    with app.app_context():
        case = Case(title=case_title, investigator=investigator, description=description, status="Open")
        db.session.add(case)
        db.session.commit()
        db.session.add(Activity(case_id=case.id, action_type="case_created", result=case.title))
        db.session.commit()
        case_id = case.id
        print(f"✓ Case #{case_id} registered: '{case.title}' (Lead: {case.investigator})")

    # 2. GENERATE AND REGISTER EVIDENCE
    print("\n[STEP 2] Simulating & Registering Digital Evidence Files...")
    sim_dir = Path("instance") / "simulated_artifacts"
    sim_dir.mkdir(parents=True, exist_ok=True)

    # Artifact A: Exfiltrated Memo
    leak_file = sim_dir / "confidential_project_chimera.txt"
    leak_content = (
        "CONFIDENTIAL // TOP SECRET - PROJECT CHIMERA\n"
        "Date: 2026-10-12\n"
        "Classification: Restricted Internal Distribution\n"
        "Payload Architecture: Autonomous Multi-Agent Neural Controller v4.2\n"
        "Cryptographic Key Fragment: 8f9b23a7e4c19d204a8b71f92e482701b\n"
        "Target Destination: 198.51.100.44:8443 (Encrypted Tunnel)\n"
    )
    leak_file.write_text(leak_content, encoding="utf-8")

    # Artifact B: Network Triage CSV
    triage_file = sim_dir / "perimeter_network_triage.csv"
    triage_content = (
        "timestamp,src_ip,dest_ip,protocol,dest_port,bytes_transferred,alert_id\n"
        "2026-10-12T08:14:02Z,192.168.1.105,10.0.0.1,TCP,443,1420,NONE\n"
        "2026-10-12T08:15:30Z,192.168.1.105,198.51.100.44,TCP,8443,8492004,ALERT_EXFIL_ANOMALY\n"
        "2026-10-12T08:16:11Z,192.168.1.105,10.0.0.5,SSH,22,2048,ALERT_FAILED_BRUTE_FORCE\n"
    )
    triage_file.write_text(triage_content, encoding="utf-8")

    # Register evidence into case using client
    # Fetch CSRF token
    csrf_res = client.get("/cases/new").data.decode()
    csrf_token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', csrf_res).group(1)

    for f_path in (leak_file, triage_file):
        with open(f_path, "rb") as stream:
            res = client.post(
                f"/cases/{case_id}/evidence",
                data={"file": (stream, f_path.name), "csrf_token": csrf_token},
                content_type="multipart/form-data",
            )
        assert res.status_code == 302
        print(f"✓ Registered evidence: {f_path.name}")

    with app.app_context():
        evidence_items = Evidence.query.filter_by(case_id=case_id).all()
        for item in evidence_items:
            hashes = multi_hash_file(item.source)
            print(f"  • ID #{item.id} [{item.description}]")
            print(f"    - SHA-256: {item.sha256}")
            print(f"    - MD5:     {hashes['md5']}")
            print(f"    - SHA-1:   {hashes['sha1']}")

    # 3. TEST IN-PLACE INTEGRITY VERIFICATION
    print("\n[STEP 3] Testing In-Place Evidence Integrity Verification...")
    with app.app_context():
        first_item = evidence_items[0]
        v_res = client.post(f"/evidence/{first_item.id}/verify", headers={"X-CSRFToken": csrf_token})
        print(f"✓ Verify check on #{first_item.id}: {v_res.json['status'].upper()} - {v_res.json['message']}")

    # 4. SIMULATE AND ANALYZE LOGS
    print("\n[STEP 4] Simulating & Analyzing Forensic Security Logs...")
    log_file = sim_dir / "auth_intrusion_timeline.log"
    log_content = """2026-10-12 08:10:01 INFO [sshd] Server listening on 0.0.0.0 port 22.
2026-10-12 08:12:15 ERROR [sshd] failed login for user root from 192.168.1.105 port 54102 ssh2
2026-10-12 08:12:19 ERROR [sshd] failed login for user root from 192.168.1.105 port 54108 ssh2
2026-10-12 08:12:25 ERROR [sshd] failed login for user admin from 192.168.1.105 port 54114 ssh2
2026-10-12 08:13:00 WARNING [nginx] GET /api/v1/download?file=../../../../etc/shadow HTTP/1.1 403
2026-10-12 08:13:42 CRITICAL [webapp] POST /auth/login payload="user=' OR '1'='1" HTTP/1.1 500
2026-10-12 08:14:00 CRITICAL [kernel] sudo su root execution detected: tty=/dev/pts/1
2026-10-12 08:15:20 INFO [sshd] Session closed for user auditor.
"""
    log_file.write_text(log_content, encoding="utf-8")

    with open(log_file, "rb") as stream:
        log_res = client.post(
            f"/cases/{case_id}/logs",
            data={"file": (stream, log_file.name), "csrf_token": csrf_token},
            content_type="multipart/form-data",
        )
    assert log_res.status_code == 302
    print(f"✓ Log analyzed: {log_file.name}")

    with app.app_context():
        analysis = LogAnalysis.query.filter_by(case_id=case_id).first()
        findings_data = json.loads(analysis.findings_json)
        print(f"  • Events Processed: {findings_data['events_processed']}")
        print(f"  • Flagged Security Patterns: {findings_data['flagged_patterns']}")
        print("  • Severity Breakdown:")
        for sev, count in findings_data.get("severity_counts", {}).items():
            if count > 0:
                print(f"    - {sev}: {count} event(s)")
        print("  • Investigative Security Leads Detected:")
        for finding in findings_data["findings"]:
            print(f"    ⚠ [{finding.get('severity', 'LEAD')}] {finding['reason']} ({finding['events']} occurrence(s))")

    # 5. SIMULATE & EXAMINE FORENSIC DISK IMAGE (NATIVE MBR)
    print("\n[STEP 5] Simulating & Examining Forensic Disk Image (MBR)...")
    disk_file = sim_dir / "workstation_dump.dd"
    # Construct synthetic 64KB sector stream with valid 512-byte MBR
    raw_disk = bytearray(65536)
    # MBR Signature 0x55AA at bytes 510-511
    raw_disk[510:512] = b"\x55\xaa"
    # Partition 1: Bootable NTFS (type 0x07, start LBA 2048, 2097152 sectors = 1GB)
    part1 = struct.pack("<BBBBBBBBII", 0x80, 0, 1, 1, 0x07, 0, 1, 1, 2048, 2097152)
    raw_disk[446:446 + 16] = part1
    # Partition 2: Linux Native ext4 (type 0x83, start LBA 2099200, 1048576 sectors = 512MB)
    part2 = struct.pack("<BBBBBBBBII", 0x00, 0, 1, 1, 0x83, 0, 1, 1, 2099200, 1048576)
    raw_disk[462:462 + 16] = part2
    disk_file.write_bytes(bytes(raw_disk))

    with open(disk_file, "rb") as stream:
        disk_res = client.post(
            "/disk-images",
            data={"case_id": str(case_id), "file": (stream, disk_file.name), "csrf_token": csrf_token},
            content_type="multipart/form-data",
        )
    assert disk_res.status_code == 200
    disk_data = disk_res.json
    print(f"✓ Registered Disk Image: {disk_file.name}")
    print(f"  • Partition Scheme: {disk_data['scheme']}")
    print(f"  • Image SHA-256:    {disk_data['sha256']}")
    print(f"  • Image MD5:       {disk_data.get('md5')}")
    print(f"  • Partitions Identified:")
    for part in disk_data.get("partitions", []):
        print(f"    - Slot #{part['slot']}: {part['type_name']} | Start LBA: {part['start_lba']} | Size: {part['size_formatted']} | Bootable: {part['bootable']}")

    # 6. TEST TAMPERING DETECTION AUDIT
    print("\n[STEP 6] Simulating Evidence Tampering & Integrity Violation Audit...")
    with app.app_context():
        # Intentionally tamper with the stored file for triage_file
        triage_evidence = Evidence.query.filter_by(description="perimeter_network_triage.csv").first()
        with open(triage_evidence.source, "wb") as f:
            f.write(b"CORRUPTED / TAMPERED EVIDENCE CONTENT INSERTED BY ATTACKER")

        # Now attempt to verify or download
        download_res = client.get(f"/evidence/{triage_evidence.id}/download")
        assert download_res.status_code == 409
        print(f"✓ Tampering correctly intercepted during download (HTTP 409 Conflict)")

        # In-place verify check
        verify_fail_res = client.post(f"/evidence/{triage_evidence.id}/verify", headers={"X-CSRFToken": csrf_token})
        assert verify_fail_res.status_code == 409
        print(f"✓ In-place integrity check failed as expected: '{verify_fail_res.json['message']}'")

        # Confirm audit activity was logged
        fail_act = Activity.query.filter_by(action_type="evidence_integrity_failure").all()
        print(f"✓ Audit trail recorded {len(fail_act)} 'evidence_integrity_failure' event(s)")

    # 7. GENERATE FINAL COMPREHENSIVE REPORTS
    print("\n[STEP 7] Generating Final Case Reports (JSON, CSV, PDF)...")
    json_res = client.get(f"/reports/{case_id}.json")
    assert json_res.status_code == 200
    json_report = json_res.json

    csv_res = client.get(f"/reports/{case_id}.csv")
    assert csv_res.status_code == 200
    csv_report_bytes = csv_res.data

    pdf_res = client.get(f"/reports/{case_id}.pdf")
    assert pdf_res.status_code == 200
    pdf_report_bytes = pdf_res.data

    # Save exports to instance/reports/
    export_dir = Path("instance") / "reports"
    export_dir.mkdir(parents=True, exist_ok=True)
    json_path = export_dir / f"case_{case_id}_report.json"
    csv_path = export_dir / f"case_{case_id}_report.csv"
    pdf_path = export_dir / f"case_{case_id}_report.pdf"

    json_path.write_text(json.dumps(json_report, indent=2), encoding="utf-8")
    csv_path.write_bytes(csv_report_bytes)
    pdf_path.write_bytes(pdf_report_bytes)

    print(f"✓ JSON Report Exported: {json_path.resolve()} ({len(json_report.keys())} sections)")
    print(f"✓ CSV Report Exported:  {csv_path.resolve()} ({len(csv_report_bytes)} bytes)")
    print(f"✓ PDF Report Exported:  {pdf_path.resolve()} ({len(pdf_report_bytes)} bytes)")

    print("\n" + "=" * 70)
    print("SIMULATION COMPLETED SUCCESSFULLY!")
    print("=" * 70)

    return {
        "case_id": case_id,
        "json_path": str(json_path),
        "csv_path": str(csv_path),
        "pdf_path": str(pdf_path),
        "json_report": json_report,
    }


if __name__ == "__main__":
    run_simulation()
