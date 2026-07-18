from detector.detector import analyze_logs

def parse_logs(log_file="app/sample_logs/access.log"):
    log_entries = []
    status_counts = {}

    with open(log_file, "r") as file:
        for line in file:
            parts = line.split()

            status = parts[8]

            log_entries.append({
                "ip": parts[0],
                "method": parts[5].replace('"', ''),
                "url": parts[6],
                "status": status,
            })

            status_counts[status] = status_counts.get(status, 0) + 1

    results = analyze_logs(log_entries)

    results["status_counts"] = status_counts
    results["total_logs"] = len(log_entries)
    attack_summary = {}

    for alert in results["alerts"]:
        attack_type = alert["type"]
        attack_summary[attack_type] = attack_summary.get(attack_type, 0) + 1

    normal_requests = len(log_entries) - len(results["alerts"])

    results["attack_summary"] = {
        "Normal Requests": normal_requests,
        **attack_summary
    }

    # Dashboard Statistics
    results["dashboard_stats"] = {
        "total_logs": len(log_entries),
        "total_alerts": len(results["alerts"]),
        "high_severity": sum(
            1 for alert in results["alerts"]
            if alert["severity"] == "High"
        ),
        "medium_severity": sum(
            1 for alert in results["alerts"]
            if alert["severity"] == "Medium"
        ),
    }

    return results


if __name__ == "__main__":
    results = parse_logs()

    print("\n===== Failed Login Summary =====")

    for ip, count in results["failed_logins"].items():
        print(f"{ip} -> {count} failed login(s)")

    print("\n===== Brute Force Detection =====")

    for ip in results["brute_force_ips"]:
        print(f"🚨 HIGH RISK: {ip}")

    print("\n===== Alerts =====")

    for alert in results["alerts"]:
        print(alert)