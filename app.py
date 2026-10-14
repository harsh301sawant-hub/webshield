
from flask import Flask, render_template_string, request, abort, send_from_directory
from pathlib import Path
from urllib.parse import urlparse
import json
import os
import socket
import ipaddress

from webshield import scan

app = Flask(__name__)

REPORT_DIR = Path("reports")


def validate_target(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    if parsed.username or parsed.password:
        raise ValueError("URL credentials are not allowed.")

    if parsed.port not in (None, 80, 443):
        raise ValueError("Only standard HTTP/HTTPS ports are allowed.")

    allowed_hosts = {
        host.strip().lower().rstrip(".")
        for host in os.environ.get(
            "WEBSHIELD_ALLOWED_HOSTS", ""
        ).split(",")
        if host.strip()
    }

    hostname = parsed.hostname.lower().rstrip(".")

    if hostname not in allowed_hosts:
        raise ValueError(
            "This host is not in your authorized domain allowlist."
        )

    try:
        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("Could not resolve the target hostname.")

    if not addresses:
        raise ValueError("No IP address found for this host.")

    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if not ip.is_global:
            raise ValueError(
                "Target must resolve only to public IP addresses."
            )

    return parsed


HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebShield | Security Dashboard</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1120;color:#e5e7eb;font-family:Arial,sans-serif}
header{padding:22px 7%;background:#111a2e;border-bottom:1px solid #26344d}
header h1{margin:0;color:#60a5fa}
header p{color:#9ca3af;margin-bottom:0}
main{max-width:1100px;margin:30px auto;padding:0 20px}
.card{background:#111a2e;border:1px solid #26344d;border-radius:12px;padding:22px;margin-bottom:20px}
h2{margin-top:0;font-size:20px}
form{display:flex;gap:10px;flex-wrap:wrap}
input{flex:1;min-width:220px;padding:13px;border-radius:7px;border:1px solid #374151;background:#0b1120;color:white}
button{padding:13px 20px;border:0;border-radius:7px;background:#2563eb;color:white;cursor:pointer;font-weight:bold}
button:hover{background:#1d4ed8}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:15px}
.stat{background:#17243b;padding:18px;border-radius:9px}
.stat strong{font-size:26px;display:block;margin-top:10px}
table{width:100%;border-collapse:collapse}
th,td{padding:12px;text-align:left;border-bottom:1px solid #26344d}
th{color:#93c5fd}
.table-wrap{overflow-x:auto}
.review{color:#fbbf24}
.info{color:#86efac}
.error{color:#fca5a5}
.notice{color:#fbbf24;overflow-wrap:anywhere}
a{color:#93c5fd}
footer{text-align:center;color:#9ca3af;padding:25px}
</style>
</head>
<body>
<header>
<h1>🛡 WebShield</h1>
<p>Web Application Security Assessment Dashboard</p>
</header>
<main>
<div class="card">
<h2>Start a Security Scan</h2>
<p>Enter a website you own or are authorized to test.</p>
<form method="post">
<input name="url" type="url" required
placeholder="https://your-authorized-domain.com/"
value="{{ target }}">
<button type="submit">Scan Target</button>
</form>
{% if message %}<p class="notice">{{ message }}</p>{% endif %}
</div>

{% if result %}
<div class="stats">
<div class="stat">Target<strong style="font-size:16px;overflow-wrap:anywhere">{{ result.target }}</strong></div>
<div class="stat">HTTP Status<strong>{{ result.http_status or "N/A" }}</strong></div>
<div class="stat">Checks needing review<strong>{{ review_count }}</strong></div>
<div class="stat">Findings<strong>{{ result.findings|length }}</strong></div>
</div>

<div class="card" style="margin-top:20px">
<h2>Security Findings</h2>
<div class="table-wrap">
<table>
<tr><th>Severity</th><th>Check</th><th>Details</th></tr>
{% for f in result.findings %}
<tr>
<td class="{{ f.severity|lower }}">{{ f.severity }}</td>
<td>{{ f.item }}</td>
<td>{{ f.details }}</td>
</tr>
{% endfor %}
</table>
</div>

{% if result.tls %}
<h2 style="margin-top:25px">TLS Details</h2>
<p>Status: {{ result.tls.status }}</p>
<p>TLS version: {{ result.tls.get('tls_version', 'N/A') }}</p>
{% endif %}

<h2 style="margin-top:25px">Reports</h2>
{% if json_file %}
<p>Latest JSON: <a href="/reports/{{ json_file }}">Open JSON report</a></p>
{% endif %}
{% if html_file %}
<p>Latest HTML: <a href="/reports/{{ html_file }}">Open HTML report</a></p>
{% endif %}
<p><small>Findings need manual review; this is a basic configuration check, not a full penetration test.</small></p>
</div>
{% endif %}
</main>
<footer>WebShield · Authorized testing only</footer>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def dashboard():
    result = None
    message = ""
    target = ""
    json_file = ""
    html_file = ""

    if request.method == "POST":
        target = request.form.get("url", "").strip()

        try:
            validate_target(target)

            # Run only against an explicitly allowlisted host.
            scan(target)

            # Select the report created for this target.
            report_files = sorted(
                REPORT_DIR.glob("report_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )

            for report_path in report_files:
                try:
                    candidate = json.loads(
                        report_path.read_text(encoding="utf-8")
                    )
                    if candidate.get("target") == target:
                        result = candidate
                        json_file = report_path.name
                        html_file = report_path.with_suffix(".html").name
                        break
                except (OSError, json.JSONDecodeError):
                    continue

            if result is None:
                message = (
                    "Scan ran, but its report could not be found. "
                    "Check the application logs."
                )

        except (ValueError, OSError) as exc:
            message = str(exc)
        except Exception:
            app.logger.exception("WebShield scan failed")
            message = (
                "Scan failed. Check the application logs "
                "for details."
            )

    review_count = sum(
        1 for finding in (result or {}).get("findings", [])
        if finding.get("severity") in ("REVIEW", "ERROR")
    )

    return render_template_string(
        HTML,
        result=result,
        target=target,
        message=message,
        review_count=review_count,
        json_file=json_file,
        html_file=html_file
    )


@app.route("/reports/<path:filename>")
def reports(filename):
    safe_name = Path(filename).name

    if safe_name != filename or not safe_name.startswith("report_"):
        abort(404)

    if Path(safe_name).suffix not in (".json", ".html"):
        abort(404)

    report_dir = REPORT_DIR.resolve()

    if not report_dir.is_dir():
        abort(404)

    file_path = (report_dir / safe_name).resolve()

    if file_path.parent != report_dir or not file_path.is_file():
        abort(404)

    return send_from_directory(str(report_dir), safe_name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
