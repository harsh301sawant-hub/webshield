
from flask import Flask, render_template_string, request
from pathlib import Path
import json

from webshield import scan

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebShield | Security Dashboard</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1120;color:#e5e7eb;
font-family:Arial,sans-serif}
header{padding:22px 7%;background:#111a2e;
border-bottom:1px solid #26344d}
header h1{margin:0;color:#60a5fa}
header p{color:#9ca3af;margin-bottom:0}
main{max-width:1100px;margin:30px auto;padding:0 20px}
.card{background:#111a2e;border:1px solid #26344d;
border-radius:12px;padding:22px;margin-bottom:20px}
h2{margin-top:0;font-size:20px}
form{display:flex;gap:10px;flex-wrap:wrap}
input{flex:1;min-width:220px;padding:13px;
border-radius:7px;border:1px solid #374151;
background:#0b1120;color:white}
button{padding:13px 20px;border:0;border-radius:7px;
background:#2563eb;color:white;cursor:pointer;font-weight:bold}
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
.notice{color:#fbbf24}
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
placeholder="http://127.0.0.1:8000/"
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
<tr><td class="{{ f.severity|lower }}">{{ f.severity }}</td>
<td>{{ f.item }}</td><td>{{ f.details }}</td></tr>
{% endfor %}
</table>
</div>
{% if result.tls %}
<h2 style="margin-top:25px">TLS Details</h2>
<p>Status: {{ result.tls.status }}</p>
<p>TLS version: {{ result.tls.get('tls_version', 'N/A') }}</p>
{% endif %}
<h2 style="margin-top:25px">Reports</h2>
<p>Latest JSON: <a href="/reports/{{ json_file }}">Open JSON report</a></p>
<p>Latest HTML: <a href="/reports/{{ html_file }}">Open HTML report</a></p>
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
            # Keep this student dashboard restricted to local lab targets.
            from urllib.parse import urlparse
            parsed = urlparse(target)
            if parsed.hostname not in ("127.0.0.1", "localhost"):
                raise ValueError(
                    "For this demo, scan only localhost or 127.0.0.1."
                )

            scan(target)

            report_dir = Path("reports")
            files = sorted(
                report_dir.glob("report_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            if files:
                json_file = files[0].name
                result = json.loads(files[0].read_text(encoding="utf-8"))
                html_file = json_file.replace(".json", ".html")

        except Exception as exc:
            message = str(exc)

    review_count = sum(
        1 for f in (result or {}).get("findings", [])
        if f.get("severity") in ("REVIEW", "ERROR")
    )

    return render_template_string(
        HTML, result=result, target=target, message=message,
        review_count=review_count, json_file=json_file,
        html_file=html_file
    )

@app.route("/reports/<path:filename>")
def reports(filename):
    from flask import abort, send_from_directory
    report_dir = Path("reports").resolve()
    safe_name = Path(filename).name
    if safe_name != filename or safe_name not in {
        p.name for p in report_dir.iterdir() if p.is_file()
    }:
        abort(404)
    return send_from_directory(str(report_dir), safe_name)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)