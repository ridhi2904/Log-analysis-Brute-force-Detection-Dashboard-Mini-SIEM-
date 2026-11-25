import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem import detector
from siem.parser import parse_ssh_line, parse_web_line

CFG = {"window_minutes": 5, "brute_force_threshold": 10, "spraying_unique_users": 8,
       "distributed_unique_ips": 8, "success_after_fail_threshold": 5}
T0 = datetime(2026, 11, 17, 10, 0, 0)


def ev(sec, ip="1.1.1.1", user="root", status="fail", source="ssh"):
    return {"ts": T0 + timedelta(seconds=sec), "source": source, "ip": ip,
            "username": user, "status": status, "raw": ""}


def test_parse_ssh_failed_invalid_user():
    e = parse_ssh_line("Nov 17 10:15:32 srv sshd[99]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2", 2026)
    assert e["status"] == "fail" and e["ip"] == "1.2.3.4" and e["username"] == "bob"


def test_parse_ssh_accepted():
    e = parse_ssh_line("Nov  7 01:02:03 srv sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2", 2026)
    assert e["status"] == "success" and e["username"] == "alice"


def test_parse_ssh_ignores_noise():
    assert parse_ssh_line("Nov 17 10:15:32 srv sshd[99]: Connection closed by 1.2.3.4", 2026) is None
    assert parse_ssh_line("garbage", 2026) is None


def test_parse_web():
    line = '5.5.5.5 - - [17/Nov/2026:10:15:32 +0000] "POST /wp-login.php HTTP/1.1" 401 123 "-" "x"'
    assert parse_web_line(line)["status"] == "fail"
    assert parse_web_line(line.replace("401", "302"))["status"] == "success"
    assert parse_web_line(line.replace("/wp-login.php", "/home")) is None


def test_brute_force_detected_and_merged():
    events = [ev(i * 5) for i in range(40)]  # 40 fails in 200s -> ONE merged alert
    alerts = detector.detect_brute_force(events, timedelta(minutes=5), 10)
    assert len(alerts) == 1 and alerts[0]["count"] == 40


def test_below_threshold_no_alert():
    assert detector.detect_brute_force([ev(i) for i in range(9)], timedelta(minutes=5), 10) == []


def test_slow_attack_outside_window_not_flagged():
    events = [ev(i * 120) for i in range(10)]  # 1 fail / 2 min -> max 3 per window
    assert detector.detect_brute_force(events, timedelta(minutes=5), 10) == []


def test_password_spraying():
    events = [ev(i, user=f"user{i}") for i in range(10)]
    a = detector.detect_password_spraying(events, timedelta(minutes=5), 8)
    assert len(a) == 1 and a[0]["count"] == 10


def test_distributed():
    events = [ev(i, ip=f"9.9.9.{i}", user="admin") for i in range(10)]
    a = detector.detect_distributed(events, timedelta(minutes=5), 8)
    assert len(a) == 1 and a[0]["username"] == "admin"


def test_success_after_fail_is_critical():
    events = [ev(i) for i in range(6)] + [ev(10, status="success")]
    a = detector.detect_success_after_fail(events, timedelta(minutes=5), 5)
    assert len(a) == 1 and a[0]["severity"] == "critical"


def test_single_typo_not_flagged():
    events = [ev(0), ev(5, status="success")]
    assert detector.detect_success_after_fail(events, timedelta(minutes=5), 5) == []


def test_run_all_sorted_critical_first():
    events = [ev(i) for i in range(12)] + [ev(20, status="success")]
    alerts = detector.run_all(events, CFG)
    assert alerts[0]["severity"] == "critical"
