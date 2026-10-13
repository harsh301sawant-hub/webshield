
import requests
import ssl
import socket
import json
import html
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce certain injection attacks.",
    "Strict-Transport-Security": "Enforces HTTPS in supported browsers.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "Referrer-Policy": "Controls referrer information.",
    "Permissions-Policy": "Controls access to browser features."
}

def check_tls(hostname, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure:
                cert = secure.getpeercert()
                return {
                    "status": "PASS",
                    "tls_version": secure.version(),
                    "expires": cert.get("notAfter", "Unknown")
                }
    except Exception as exc:
        return {"status": "REVIEW", "details": str(exc)}

def scan(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")

    if parsed.username or parsed.password:
        raise ValueError("Do not include credentials in the URL.")

    print("\nScanning:", url)
    print("Only scan systems you own or have permission to test.\n")

    result = {
        "target": url,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "http_status": None,
        "https": parsed.scheme == "https",
        "findings": [],
        "tls": None,
        "cookies": []
    }

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )
        result["http_status"] = response.status_code

        for header, purpose in SECURITY_HEADERS.items():
            if header not in response.headers:
                result["findings"].append({
                    "severity": "REVIEW",
                    "item": header,
                    "details": "Header not detected. " + purpose
                })
            else:
                result["findings"].append({
                    "severity": "INFO",
                    "item": header,
                    "details": "Header detected."
                })

        for cookie in response.cookies:
            issues = []
            if parsed.scheme == "https" and not cookie.secure:
                issues.append("Secure flag not detected")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag not detected")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("SameSite attribute not detected")

            result["cookies"].append({
                "name": cookie.name,
                "issues": issues or ["No basic attribute issue detected"]
            })

        if parsed.scheme == "https":
            result["tls"] = check_tls(parsed.hostname, parsed.port or 443)
        else:
            result["findings"].append({
                "severity": "REVIEW",
                "item": "HTTPS",
                "details": "Target uses HTTP. Sensitive data should not be sent over plain HTTP."
            })

    except requests.RequestException as exc:
        result["findings"].append({
            "severity": "ERROR",
            "item": "Connection",
            "details": str(exc)
        })

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = REPORT_DIR / f"report_{stamp}.json"
    html_path = REPORT_DIR / f"report_{stamp}.html"

    json_path.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    rows = ""
    for finding in result["findings"]:
        rows += (
            "<tr><td>" + html.escape(finding["severity"]) +
            "</td><td>" + html.escape(finding["item"]) +
            "</td><td>" + html.escape(finding["details"]) +
            "</td></tr>"
        )

    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>WebShield Report</title>
<style>
body{font-family:Arial;margin:30px;background:#f4f6f8;color:#222}
main{background:white;padding:24px;border-radius:10px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:10px;text-align:left}
th{background:#e9eef5}
</style>
</head>
<body><main>
<h1>WebShield Security Report</h1>
<p>Target: """ + html.escape(url) + """</p>
<p>Scan time: """ + html.escape(result["scan_time"]) + """</p>
<p>HTTP status: """ + html.escape(str(result["http_status"])) + """</p>
<table><tr><th>Severity</th><th>Check</th><th>Details</th></tr>
""" + rows + """</table>
<p>Review findings manually. Missing headers alone do not prove a vulnerability.</p>
</main></body></html>"""

    html_path.write_text(page, encoding="utf-8")

    print("Scan complete.")
    print("JSON report:", json_path)
    print("HTML report:", html_path)

if __name__ == "__main__":
    target = input("Enter authorized target URL: ").strip()
    try:
        scan(target)
    except ValueError as exc:
        print("Input error:", exc)