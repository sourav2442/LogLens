from collections import defaultdict

from database.db import db


def get_reputation_level(score):
    """Classify an IP's historical reputation score."""

    if score >= 75:
        return "Critical"

    elif score >= 50:
        return "High"

    elif score >= 30:
        return "Medium"

    else:
        return "Low"


def enrich_ip_reputation(ip_risk_scores):
    """
    Enrich current IP risk reports using historical MongoDB records.

    The current scan is not included because this function runs
    before the current scan is saved.
    """

    if not ip_risk_scores:
        return []

    # Collect unique IP addresses.
    ips = list({
        item.get("ip")
        for item in ip_risk_scores
        if item.get("ip")
    })

    if not ips:
        return ip_risk_scores

    # Fetch historical records for all IPs in one query.
    historical_records = db.ip_risks.find({
        "ip": {"$in": ips}
    })

    # Group historical records by IP.
    history_by_ip = defaultdict(list)

    for record in historical_records:
        history_by_ip[record.get("ip")].append(record)

    enriched_reports = []

    for item in ip_risk_scores:

        report = item.copy()
        ip = report.get("ip")

        history = history_by_ip.get(ip, [])

        # No previous scan records.
        if not history:

            report.update({
                "previous_scan_count": 0,
                "avg_historical_score": 0,
                "max_historical_score": 0,
                "last_seen": None,
                "reputation_score": None,
                "reputation_level": "Unknown",
                "reputation_reasons": [
                    "No historical records available."
                ]
            })

            enriched_reports.append(report)
            continue

        # Count unique previous scans.
        previous_scan_ids = {
            record.get("scan_id")
            for record in history
            if record.get("scan_id")
        }

        previous_scan_count = len(previous_scan_ids)

        scores = [
            record.get("score", 0)
            for record in history
            if isinstance(record.get("score"), (int, float))
        ]

        if scores:
            average_score = sum(scores) / len(scores)
            maximum_score = max(scores)
        else:
            average_score = 0
            maximum_score = 0

        # Find the most recent historical scan.
        scan_dates = [
            record.get("scan_date")
            for record in history
            if record.get("scan_date") is not None
        ]

        last_seen = max(scan_dates) if scan_dates else None

        # Repeated appearances increase historical reputation.
        recurrence_bonus = min(previous_scan_count * 10, 30)

        reputation_score = round(
            min(100, average_score * 0.7 + recurrence_bonus)
        )

        reputation_level = get_reputation_level(reputation_score)

        reasons = [
            f"Previously detected in {previous_scan_count} scan(s).",
            f"Average historical risk score: {average_score:.1f}/100.",
            f"Highest historical risk score: {maximum_score}/100."
        ]

        if previous_scan_count >= 3:
            reasons.append("Repeated appearances across multiple scans.")

        report.update({
            "previous_scan_count": previous_scan_count,
            "avg_historical_score": round(average_score, 2),
            "max_historical_score": maximum_score,
            "last_seen": last_seen,
            "reputation_score": reputation_score,
            "reputation_level": reputation_level,
            "reputation_reasons": reasons
        })

        enriched_reports.append(report)

    return enriched_reports