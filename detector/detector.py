import re
from urllib.parse import unquote
from datetime import datetime, timedelta


# Normalize URL to detect encoded payloads
def normalize_url(url):
    decoded = url

    # Decode multiple times to catch double-encoded payloads
    for _ in range(3):
        new_decoded = unquote(decoded)

        if new_decoded == decoded:
            break

        decoded = new_decoded

    return decoded.lower()


# SQL Injection Detection
def detect_sql_injection(url):
    url = normalize_url(url)

    patterns = [
        r"'\s*or\s*['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
        r"\bunion\s+(all\s+)?select\b",
        r"\bselect\b.+\bfrom\b",
        r"\bdrop\s+table\b",
        r"\binsert\s+into\b",
        r"\bdelete\s+from\b",
        r"\bupdate\b.+\bset\b",
        r";\s*--",
    ]

    return any(re.search(pattern, url) for pattern in patterns)


# Cross-Site Scripting Detection
def detect_xss(url):
    url = normalize_url(url)

    patterns = [
        r"<\s*script\b",
        r"javascript\s*:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<\s*iframe\b",
        r"<\s*svg\b",
        r"document\.cookie",
        r"alert\s*\(",
    ]

    return any(re.search(pattern, url) for pattern in patterns)


# Directory Traversal Detection
def detect_directory_traversal(url):
    url = normalize_url(url)

    patterns = [
        "../",
        "..\\",
        "/etc/passwd",
        "/etc/shadow",
        "windows/system32",
        "boot.ini",
    ]

    return any(pattern in url for pattern in patterns)


# Command Injection Detection
def detect_command_injection(url):
    url = normalize_url(url)

    patterns = [
        r";\s*(whoami|id|uname|cat|ls|pwd)\b",
        r"\|\s*(whoami|id|uname|cat|ls)\b",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"/bin/(sh|bash)\b",
        r"\bping\s+-c\b",
    ]

    return any(re.search(pattern, url) for pattern in patterns)


# Vulnerability Scanner Activity Detection
def detect_scanner_activity(url):
    url = normalize_url(url)

    suspicious_paths = [
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/.env",
        "/.git",
        "/config.php",
        "/server-status",
        "/actuator",
        "/adminer.php",
        "/xmlrpc.php",
    ]

    return any(path in url for path in suspicious_paths)


# Suspicious HTTP Method Detection
def detect_suspicious_method(method):
    suspicious_methods = [
        "TRACE",
        "TRACK",
        "CONNECT",
    ]

    return method.upper() in suspicious_methods

def calculate_ip_risk_scores(alerts, failed_logins):
    """
    Calculate risk scores for suspicious IP addresses.
    Maximum score: 100.
    Avoid duplicate scoring for repeated alert types.
    """

    ip_data = {}

    severity_weights = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Low": 5
    }

    attack_weights = {
        "Brute Force": 20,
        "SQL Injection": 15,
        "XSS": 15,
        "Directory Traversal": 15,
        "Command Injection": 20,
        "Scanner Activity": 8,
        "Suspicious Method": 8,
        "Suspicious HTTP Method": 8,
        "Failed Login": 0
    }

    # Process security alerts
    for alert in alerts:

        ip = alert.get("ip")

        if not ip or ip == "-":
            continue

        if ip not in ip_data:
            ip_data[ip] = {
                "alert_count": 0,
                "failed_logins": 0,
                "attack_types": set(),
                "severity_scores": {},
                "reasons": []
            }

        data = ip_data[ip]

        severity = alert.get("severity", "Low")
        attack_type = alert.get("type", "Unknown")

        data["alert_count"] += 1
        data["attack_types"].add(attack_type)

        # Keep only the highest severity score per alert type
        severity_score = severity_weights.get(severity, 5)

        data["severity_scores"][attack_type] = max(
            data["severity_scores"].get(attack_type, 0),
            severity_score
        )

    # Add failed login information
    for ip, attempts in failed_logins.items():

        if ip not in ip_data:
            ip_data[ip] = {
                "alert_count": 0,
                "failed_logins": 0,
                "attack_types": set(),
                "severity_scores": {},
                "reasons": []
            }

        ip_data[ip]["failed_logins"] = attempts

    # Generate final risk reports
    risk_reports = []

    for ip, data in ip_data.items():

        score = 0
        reasons = []

        # Severity contribution
        severity_score = sum(data["severity_scores"].values())
        score += severity_score

        if severity_score:
            reasons.append(
                f"Severity-based risk: {severity_score} points"
            )

        # Attack-specific contribution
        for attack_type in data["attack_types"]:

            attack_score = attack_weights.get(attack_type, 0)

            if attack_score > 0:
                score += attack_score

                reasons.append(
                    f"{attack_type}: +{attack_score} points"
                )

        # Failed login contribution
        attempts = data["failed_logins"]
        login_score = min(attempts * 5, 20)

        score += login_score

        if attempts > 0:
            reasons.append(
                f"{attempts} failed login attempts: +{login_score} points"
            )

        # Maximum risk score
        score = min(score, 100)

        # Risk classification
        if score >= 75:
            risk_level = "Critical"

        elif score >= 50:
            risk_level = "High"

        elif score >= 30:
            risk_level = "Medium"

        else:
            risk_level = "Low"

        risk_reports.append({
            "ip": ip,
            "score": score,
            "risk_level": risk_level,
            "alert_count": data["alert_count"],
            "failed_logins": attempts,
            "attack_types": sorted(data["attack_types"]),
            "reasons": reasons
        })

    # Highest-risk IP addresses first
    risk_reports.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return risk_reports


# Main Log Analysis Function
def analyze_logs(log_entries):

    failed_logins = {}
    brute_force_ips = []
    alerts = []

    threshold = 3

    for entry in log_entries:

        ip = entry["ip"]
        status = str(entry["status"])
        url = entry["url"]
        method = entry.get("method", "GET")
        user_agent = entry.get("user_agent", "-")

        if detect_suspicious_user_agent(user_agent):
            alerts.append({
                "type": "Suspicious User-Agent",
                "severity": "Medium",
                "ip": ip,
                "url": url,
                "message": f"Suspicious User-Agent detected: {user_agent}"
            })

        # Failed Login Detection
        if status == "401":

            alerts.append({
                "type": "Failed Login",
                "severity": "Medium",
                "ip": ip,
                "url": url,
                "message": "Failed Login Attempt"
            })

            failed_logins[ip] = failed_logins.get(ip, 0) + 1

        # SQL Injection
        if detect_sql_injection(url):

            alerts.append({
                "type": "SQL Injection",
                "severity": "High",
                "ip": ip,
                "url": url,
                "message": "Possible SQL Injection Attempt"
            })

        # XSS
        if detect_xss(url):

            alerts.append({
                "type": "XSS",
                "severity": "High",
                "ip": ip,
                "url": url,
                "message": "Possible Cross-Site Scripting Attempt"
            })

        # Directory Traversal
        if detect_directory_traversal(url):

            alerts.append({
                "type": "Directory Traversal",
                "severity": "High",
                "ip": ip,
                "url": url,
                "message": "Directory Traversal Attempt Detected"
            })

        # Command Injection
        if detect_command_injection(url):

            alerts.append({
                "type": "Command Injection",
                "severity": "Critical",
                "ip": ip,
                "url": url,
                "message": "Possible Command Injection Attempt"
            })

        # Scanner Activity
        if detect_scanner_activity(url):

            alerts.append({
                "type": "Scanner Activity",
                "severity": "Medium",
                "ip": ip,
                "url": url,
                "message": "Request to a Common Scanning Target"
            })

        # Suspicious HTTP Methods
        if detect_suspicious_method(method):

            alerts.append({
                "type": "Suspicious HTTP Method",
                "severity": "Medium",
                "ip": ip,
                "url": url,
                "message": f"Suspicious HTTP Method: {method}"
            })

        # Advanced Time-Based Brute Force Detection

    time_window = timedelta(minutes=5)
    brute_force_threshold = 3

    failed_login_times = {}

    # Collect failed login timestamps by IP
    for entry in log_entries:

        if str(entry.get("status")) != "401":
            continue

        ip = entry.get("ip")
        timestamp = entry.get("timestamp")

        if not ip or not timestamp:
            continue

        try:
            login_time = datetime.strptime(
                timestamp,
                "%d/%b/%Y:%H:%M:%S %z"
            )

        except (ValueError, TypeError):
            continue

        failed_login_times.setdefault(ip, []).append(login_time)

    # Analyze each IP using a sliding window
    for ip, timestamps in failed_login_times.items():

        timestamps.sort()

        left = 0
        max_attempts = 0
        attack_window = None

        for right in range(len(timestamps)):

            while (
                timestamps[right] - timestamps[left]
                > time_window
            ):
                left += 1

            current_attempts = right - left + 1

            if current_attempts > max_attempts:

                max_attempts = current_attempts

                attack_window = {
                    "start": timestamps[left].isoformat(),
                    "end": timestamps[right].isoformat()
                }

        # Generate one alert per attacking IP
        if max_attempts >= brute_force_threshold:

            if ip not in brute_force_ips:

                brute_force_ips.append(ip)

                alerts.append({
                    "type": "Brute Force",
                    "severity": "High",
                    "ip": ip,
                    "url": "-",
                    "attempts": max_attempts,
                    "time_window": "5 minutes",
                    "window_start": attack_window["start"],
                    "window_end": attack_window["end"],
                    "message": (
                        f"{max_attempts} failed login attempts "
                        f"within 5 minutes"
                    )
                })

    ip_risk_scores = calculate_ip_risk_scores(
        alerts,
        failed_logins
    )
    return {
        "failed_logins": failed_logins,
        "brute_force_ips": brute_force_ips,
        "alerts": alerts,
        "ip_risk_scores": ip_risk_scores
    }


def detect_suspicious_user_agent(user_agent):
    if not user_agent or user_agent == "-":
        return False

    suspicious_agents = [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "zgrab",
        "dirbuster",
        "gobuster",
        "wfuzz",
        "burpsuite"
    ]

    user_agent = user_agent.lower()

    return any(agent in user_agent for agent in suspicious_agents)