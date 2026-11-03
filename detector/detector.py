import re
from urllib.parse import unquote


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

    # Brute Force Detection
    for ip, count in failed_logins.items():

        if count >= threshold:

            brute_force_ips.append(ip)

            alerts.append({
                "type": "Brute Force",
                "severity": "High",
                "ip": ip,
                "url": "-",
                "message": f"{count} failed login attempts detected"
            })

    return {
        "failed_logins": failed_logins,
        "brute_force_ips": brute_force_ips,
        "alerts": alerts
    }