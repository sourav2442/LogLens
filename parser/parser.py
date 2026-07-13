from detector.detector import analyze_logs

log_file = "app/sample_logs/access.log"

log_entries = []

with open(log_file, "r") as file:
    for line in file:
        parts = line.split()

        log_entries.append({
            "ip": parts[0],
            "method": parts[5].replace('"', ''),
            "url": parts[6],
            "status": parts[8]
        })

results = analyze_logs(log_entries)

print("\n===== Failed Login Summary =====")

for ip, count in results["failed_logins"].items():
    print(f"{ip} -> {count} failed login(s)")

print("\n===== Brute Force Detection =====")

for ip in results["brute_force_ips"]:
    print(f"🚨 HIGH RISK: {ip}")

print("\n===== Alerts =====")

for alert in results["alerts"]:
    print(alert)