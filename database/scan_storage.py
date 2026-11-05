from datetime import datetime, timezone
from uuid import uuid4

from database.db import db


def save_scan(results):

    scan_id = str(uuid4())
    scan_date = datetime.now(timezone.utc)

    # Get analysis results
    alerts = results.get("alerts", [])
    ip_risks = results.get("ip_risk_scores", [])
    failed_logins = results.get("failed_logins", {})

    # Store scan information
    scan_data = {
        "scan_id": scan_id,
        "scan_date": scan_date,
        "total_logs": results.get("total_logs", 0),
        "malformed_lines": results.get("malformed_lines", 0),
        "total_alerts": len(alerts)
    }

    db.scans.insert_one(scan_data)

    # Store security alerts
    if alerts:
        alert_documents = []

        for alert in alerts:
            alert_documents.append({
                "scan_id": scan_id,
                "ip": alert.get("ip"),
                "type": alert.get("type"),
                "severity": alert.get("severity"),
                "url": alert.get("url"),
                "message": alert.get("message"),
                "scan_date": scan_date
            })

        db.alerts.insert_many(alert_documents)

    # Store IP risk scores
    if ip_risks:
        risk_documents = []

        for risk in ip_risks:
            risk_documents.append({
                "scan_id": scan_id,
                "ip": risk.get("ip"),
                "score": risk.get("score"),
                "risk_level": risk.get("risk_level"),
                "alert_count": risk.get("alert_count"),
                "failed_logins": risk.get("failed_logins"),
                "attack_types": risk.get("attack_types", []),
                "scan_date": scan_date
            })

        db.ip_risks.insert_many(risk_documents)

    return scan_id