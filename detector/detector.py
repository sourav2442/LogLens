def detect_sql_injection(url):
    sql_patterns = [
        "%27%20or%20%271%27%3d%271",
        "union",
        "select",
        "drop",
        "--"
    ]

    for pattern in sql_patterns:
        if pattern.lower() in url.lower():
            return True

    return False


def detect_xss(url):
    xss_patterns = [
        "<script>",
        "%3cscript%3e",
        "javascript:",
        "onerror=",
        "onload="
    ]

    for pattern in xss_patterns:
        if pattern.lower() in url.lower():
            return True

    return False

def detect_directory_traversal(url):
    traversal_patterns = [
        "../",
        "..\\",
        "..%2f",
        "%2e%2e%2f",
        "etc/passwd",
        "windows/system32"
    ]

    for pattern in traversal_patterns:
        if pattern.lower() in url.lower():
            return True

    return False

def analyze_logs(log_entries):
    failed_logins = {}
    brute_force_ips = []
    alerts = []

    threshold = 3

    for entry in log_entries:
        ip = entry["ip"]
        status = entry["status"]
        url = entry["url"]

        # Failed Login Detection
        if status == "401":
            alerts.append({
                "type": "Failed Login",
                "severity": "Medium",
                "ip": ip,
                "url": url,
                "message": "Failed Login Attempt"
            })

            if ip in failed_logins:
                failed_logins[ip] += 1
            else:
                failed_logins[ip] = 1

        # SQL Injection Detection
        if detect_sql_injection(url):
            alerts.append({
                "type": "SQL Injection",
                "severity": "High",
                "ip": ip,
                "url": url,
                "message": "SQL Injection Attempt Detected"
            })

        # XSS Detection
        if detect_xss(url):
            alerts.append({
                "type": "XSS",
                "severity": "High",
                "ip": ip,
                "url": url,
                "message": "Cross-Site Scripting (XSS) Attempt"
            })
        
        # Directory Traversal Detection
        if detect_directory_traversal(url):
            alerts.append({
                "type": "Directory Traversal",
                "severity": "High",
                "ip": ip,
                "url": url,
                "message": "Directory Traversal Attempt Detected"
            })

    # Brute Force Detection
    for ip, count in failed_logins.items():
        if count >= threshold:
            brute_force_ips.append(ip)
            alerts.append({
                "type": "Brute Force",
                "severity": "High",
                "ip": ip,
                "url": "-",
                "message": "Possible Brute Force Attack"
            })

    return {
        "failed_logins": failed_logins,
        "brute_force_ips": brute_force_ips,
        "alerts": alerts
    }