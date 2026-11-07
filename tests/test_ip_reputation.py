from datetime import datetime, timezone
from types import SimpleNamespace

import database.ip_reputation as ip_reputation


def mock_database(monkeypatch, records):
    """Provide mock MongoDB historical records."""

    fake_db = SimpleNamespace(
        ip_risks=SimpleNamespace(
            find=lambda query: [
                record for record in records
                if record["ip"] in query["ip"]["$in"]
            ]
        )
    )

    monkeypatch.setattr(ip_reputation, "db", fake_db)


def test_new_ip_without_history(monkeypatch):
    mock_database(monkeypatch, [])

    result = ip_reputation.enrich_ip_reputation([
        {"ip": "192.168.1.10", "score": 50}
    ])

    assert result[0]["previous_scan_count"] == 0
    assert result[0]["reputation_score"] is None
    assert result[0]["reputation_level"] == "Unknown"


def test_historical_reputation_calculation(monkeypatch):
    records = [
        {
            "ip": "192.168.1.20",
            "scan_id": "scan1",
            "score": 50,
            "scan_date": datetime(2026, 11, 1, tzinfo=timezone.utc)
        },
        {
            "ip": "192.168.1.20",
            "scan_id": "scan2",
            "score": 60,
            "scan_date": datetime(2026, 11, 2, tzinfo=timezone.utc)
        },
        {
            "ip": "192.168.1.20",
            "scan_id": "scan3",
            "score": 70,
            "scan_date": datetime(2026, 11, 3, tzinfo=timezone.utc)
        }
    ]

    mock_database(monkeypatch, records)

    result = ip_reputation.enrich_ip_reputation([
        {"ip": "192.168.1.20", "score": 80}
    ])

    report = result[0]

    assert report["previous_scan_count"] == 3
    assert report["avg_historical_score"] == 60
    assert report["max_historical_score"] == 70
    assert report["reputation_score"] == 72
    assert report["reputation_level"] == "High"


def test_reputation_level_classification():

    assert ip_reputation.get_reputation_level(10) == "Low"
    assert ip_reputation.get_reputation_level(30) == "Medium"
    assert ip_reputation.get_reputation_level(50) == "High"
    assert ip_reputation.get_reputation_level(75) == "Critical"


def test_multiple_ip_reputation(monkeypatch):
    records = [
        {
            "ip": "192.168.1.20",
            "scan_id": "scan1",
            "score": 20
        },
        {
            "ip": "192.168.1.60",
            "scan_id": "scan2",
            "score": 90
        }
    ]

    mock_database(monkeypatch, records)

    result = ip_reputation.enrich_ip_reputation([
        {"ip": "192.168.1.20"},
        {"ip": "192.168.1.60"}
    ])

    assert len(result) == 2
    assert result[0]["reputation_level"] == "Low"
    assert result[1]["reputation_level"] == "High"


def test_empty_ip_list():

    result = ip_reputation.enrich_ip_reputation([])

    assert result == []