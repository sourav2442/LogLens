import pytest

from detector.detector import (
    detect_sql_injection,
    detect_xss,
    analyze_logs,
    calculate_ip_risk_scores
)


# ---------------------------------
# SQL Injection Tests
# ---------------------------------

def test_sql_injection_detection():

    url = "/login?id=1 UNION SELECT username,password FROM users"

    assert detect_sql_injection(url) is True


def test_normal_url_not_sql_injection():

    url = "/products?page=2"

    assert detect_sql_injection(url) is False


# ---------------------------------
# XSS Detection Tests
# ---------------------------------

def test_xss_detection():

    url = "/search?q=<script>alert(1)</script>"

    assert detect_xss(url) is True


def test_normal_url_not_xss():

    url = "/home"

    assert detect_xss(url) is False


# ---------------------------------
# Failed Login Tests
# ---------------------------------

def test_failed_login_detection():

    logs = [
        {
            "ip": "192.168.1.20",
            "status": "401",
            "url": "/login"
        }
    ]

    result = analyze_logs(logs)

    assert result["failed_logins"]["192.168.1.20"] == 1


# ---------------------------------
# Brute Force Tests
# ---------------------------------

def test_brute_force_detection():

    logs = [
        {
            "ip": "192.168.1.60",
            "status": "401",
            "url": "/login",
            "timestamp": "12/Jul/2026:10:00:00 +0000"
        },
        {
            "ip": "192.168.1.60",
            "status": "401",
            "url": "/login",
            "timestamp": "12/Jul/2026:10:02:00 +0000"
        },
        {
            "ip": "192.168.1.60",
            "status": "401",
            "url": "/login",
            "timestamp": "12/Jul/2026:10:04:00 +0000"
        }
    ]

    result = analyze_logs(logs)

    assert "192.168.1.60" in result["brute_force_ips"]


def test_no_brute_force_outside_window():

    logs = [
        {
            "ip": "192.168.1.60",
            "status": "401",
            "url": "/login",
            "timestamp": "12/Jul/2026:10:00:00 +0000"
        },
        {
            "ip": "192.168.1.60",
            "status": "401",
            "url": "/login",
            "timestamp": "12/Jul/2026:10:06:00 +0000"
        },
        {
            "ip": "192.168.1.60",
            "status": "401",
            "url": "/login",
            "timestamp": "12/Jul/2026:10:12:00 +0000"
        }
    ]

    result = analyze_logs(logs)

    assert result["brute_force_ips"] == []


# ---------------------------------
# IP Risk Scoring Tests
# ---------------------------------

def test_ip_risk_scoring():

    alerts = [
        {
            "ip": "192.168.1.60",
            "type": "Failed Login",
            "severity": "Medium"
        },
        {
            "ip": "192.168.1.60",
            "type": "Brute Force",
            "severity": "High"
        }
    ]

    result = calculate_ip_risk_scores(
        alerts,
        {"192.168.1.60": 3}
    )

    assert result[0]["score"] == 65
    assert result[0]["risk_level"] == "High"


def test_risk_score_maximum_limit():

    alerts = [
        {
            "ip": "192.168.1.70",
            "type": "Attack One",
            "severity": "Critical"
        },
        {
            "ip": "192.168.1.70",
            "type": "Attack Two",
            "severity": "Critical"
        },
        {
            "ip": "192.168.1.70",
            "type": "Attack Three",
            "severity": "Critical"
        },
        {
            "ip": "192.168.1.70",
            "type": "Attack Four",
            "severity": "Critical"
        }
    ]

    result = calculate_ip_risk_scores(alerts, {})

    assert result[0]["score"] == 100
    assert result[0]["risk_level"] == "Critical"