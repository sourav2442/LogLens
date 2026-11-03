import re
from collections import Counter

from detector.detector import analyze_logs


# Apache Common/Combined Access Log parser
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<url>\S+)'
    r'(?:\s+(?P<protocol>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)


def parse_log_line(line):
    """
    Parse one Apache access log entry.
    Returns a dictionary or None if the line is invalid.
    """

    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    return {
        "ip": data["ip"],
        "timestamp": data["timestamp"],
        "method": data["method"],
        "url": data["url"],
        "protocol": data["protocol"] or "-",
        "status": data["status"],
        "size": data["size"]
    }


def parse_logs(log_file="app/sample_logs/access.log"):

    log_entries = []
    status_counts = Counter()
    malformed_lines = 0

    # Read and parse the log file
    with open(log_file, "r", encoding="utf-8", errors="replace") as file:

        for line in file:

            if not line.strip():
                continue

            entry = parse_log_line(line)

            if entry is None:
                malformed_lines += 1
                continue

            log_entries.append(entry)
            status_counts[entry["status"]] += 1

    # Analyze parsed entries using the existing detector
    results = analyze_logs(log_entries)

    # Count alerts by IP address
    top_ips = Counter(
        alert["ip"] for alert in results["alerts"]
    )

    # Count alerts by URL
    top_urls = Counter(
        alert["url"]
        for alert in results["alerts"]
        if alert["url"] != "-"
    )

    # Count attack types
    attack_summary = Counter(
        alert["type"] for alert in results["alerts"]
    )

    normal_requests = len(log_entries) - sum(
        1 for entry in log_entries
        if any(
            alert["ip"] == entry["ip"]
            and alert["url"] == entry["url"]
            for alert in results["alerts"]
        )
    )

    results["total_logs"] = len(log_entries)

    results["status_counts"] = dict(status_counts)

    results["top_ips"] = dict(top_ips.most_common())

    results["top_urls"] = dict(top_urls.most_common())

    results["attack_summary"] = {
        "Normal Requests": max(normal_requests, 0),
        **dict(attack_summary)
    }

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
        )
    }

    results["parser_stats"] = {
        "valid_lines": len(log_entries),
        "malformed_lines": malformed_lines
    }

    return results


if __name__ == "__main__":

    results = parse_logs()

    print("\n===== LogLens 2.0 Parser Report =====")

    print("Total Logs:", results["total_logs"])
    print("Malformed Lines:", results["parser_stats"]["malformed_lines"])

    print("\n===== Failed Login Summary =====")

    for ip, count in results["failed_logins"].items():
        print(f"{ip}: {count} failed attempts")

    print("\n===== Brute Force Detection =====")

    for ip in results["brute_force_ips"]:
        print("Brute Force IP:", ip)

    print("\n===== Security Alerts =====")

    for alert in results["alerts"]:
        print(
            alert["severity"],
            "|",
            alert["type"],
            "|",
            alert["ip"],
            "|",
            alert["url"]
        )