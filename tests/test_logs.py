from services.log_analyzer import analyze_log


def test_log_analysis_flags_repeated_failed_logins(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("""2026-10-01 10:00 ERROR failed login user=alice\n2026-10-01 10:01 ERROR failed login user=alice\n2026-10-01 10:02 INFO login user=alice\n""", encoding="utf-8")
    result = analyze_log(path)
    assert result["events_processed"] == 3
    assert result["flagged_patterns"] == 1
    assert "failed login" in result["findings"][0]["reason"]
