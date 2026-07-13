def analyze_logs(log_entries):
    failed_logins = {}
    brute_force_ips = []
    alerts = []

    threshold = 3

    for entry in log_entries:
        ip = entry["ip"]
        status = entry["status"]

        if status == "401":

            alerts.append(f"Failed Login Attempt: {ip}")

            if ip in failed_logins:
                failed_logins[ip] += 1
            else:
                failed_logins[ip] = 1

    for ip, count in failed_logins.items():
        if count >= threshold:
            brute_force_ips.append(ip)
            alerts.append(f"Possible Brute Force Attack: {ip}")

    return {
        "failed_logins": failed_logins,
        "brute_force_ips": brute_force_ips,
        "alerts": alerts
    }