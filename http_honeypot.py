#!/usr/bin/env python3
"""
HTTP Honeypot — Flask app on port 8080.

Emulates a corporate admin portal with honey token files and common
vulnerability paths (/phpmyadmin, /wp-login.php, /admin, /.env, etc.).

Every inbound request is logged (method, path, user-agent, POST body, IP, geo).
POSTs to login pages capture credential attempts.
Honey token files are served with tracking UUIDs — if anyone opens them and
tries to use the embedded fake credentials, that activity shows up in the SSH
or MySQL logs and you can correlate the sessions.

Run:
    python3 http_honeypot.py [--host 0.0.0.0] [--port 8080]
"""

import argparse
import sys
import uuid
from pathlib import Path

from flask import Flask, Response, redirect, request, send_file

sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import log_event
from utils.geoip import resolve
from utils.alerting import notify

app = Flask(__name__)
app.config["SERVER_NAME"] = None  # allow any host header

FAKE_DATA_DIR = Path("fake_data")
FAKE_DATA_DIR.mkdir(exist_ok=True)

# ── Honey token files ──────────────────────────────────────────────────────────
# Generated once at startup; gitignored. If attackers download and use these
# credentials, you'll see them in the SSH/MySQL logs.

def _make_honey_files() -> None:
    creds = FAKE_DATA_DIR / "credentials.txt"
    if not creds.exists():
        creds.write_text(
            "# Internal credentials — DO NOT SHARE\n"
            f"db_host=10.0.0.5\n"
            f"db_user=admin\n"
            f"db_pass=H0n3yP0t!{uuid.uuid4().hex[:8]}\n"
            "ssh_user=deploy\n"
            f"ssh_pass=d3ploy!{uuid.uuid4().hex[:8]}\n"
        )

    dump = FAKE_DATA_DIR / "dump.sql"
    if not dump.exists():
        dump.write_text(
            "-- MySQL dump 10.13  Distrib 5.7.38\n"
            "CREATE DATABASE `corp_db`;\n"
            "USE `corp_db`;\n"
            "CREATE TABLE `users` (`id` int, `username` varchar(64), `password_hash` varchar(128));\n"
            f"INSERT INTO `users` VALUES (1,'admin','$2b$12${uuid.uuid4().hex}');\n"
            f"INSERT INTO `users` VALUES (2,'sysadmin','$2b$12${uuid.uuid4().hex}');\n"
        )

    employees = FAKE_DATA_DIR / "employees.csv"
    if not employees.exists():
        employees.write_text(
            "id,name,email,department,salary\n"
            "1,John Smith,j.smith@corp.internal,Engineering,95000\n"
            "2,Sarah Jones,s.jones@corp.internal,Finance,82000\n"
            "3,Mike Brown,m.brown@corp.internal,IT,78000\n"
        )


_make_honey_files()

# ── Middleware: log every request ─────────────────────────────────────────────

@app.before_request
def _log_request() -> None:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    geo = resolve(ip)
    post_body = None
    if request.method == "POST":
        try:
            post_body = request.form.to_dict() or request.get_json(silent=True)
        except Exception:
            pass

    ev = {
        "source_ip":  ip,
        "method":     request.method,
        "path":       request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "post_body":  post_body,
        "geo":        geo,
        "referer":    request.headers.get("Referer"),
    }
    log_event("http", ev)
    notify("http", ev)
    print(f"[http] {ip} {request.method} {request.path} [{geo.get('country','??')}]")


# ── Routes ─────────────────────────────────────────────────────────────────────

_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head>
<title>Corp Admin Portal</title>
<style>
body{{font-family:Arial,sans-serif;background:#1a1a2e;display:flex;
     justify-content:center;align-items:center;height:100vh;margin:0}}
.box{{background:#fff;padding:40px;border-radius:8px;width:340px;box-shadow:0 4px 20px rgba(0,0,0,.5)}}
h2{{text-align:center;color:#333;margin-bottom:24px}}
input{{width:100%;padding:10px;margin:8px 0 16px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}}
button{{width:100%;padding:12px;background:#e74c3c;color:#fff;border:none;border-radius:4px;
        font-size:15px;cursor:pointer}}
.err{{color:#e74c3c;font-size:13px;text-align:center;margin-bottom:12px}}
</style>
</head>
<body>
<div class="box">
<h2>Admin Portal</h2>
{error}
<form method="POST" action="{action}">
<label>Username</label>
<input name="username" type="text" autocomplete="off"/>
<label>Password</label>
<input name="password" type="password"/>
<button type="submit">Sign In</button>
</form>
</div>
</body>
</html>"""

_WP_PAGE = """<!DOCTYPE html>
<html>
<head><title>Log In &lsaquo; Corp Site — WordPress</title>
<style>body{{background:#f1f1f1;font-family:Arial,sans-serif}}
#login{{width:320px;margin:60px auto;background:#fff;padding:26px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.2)}}
h1{{text-align:center;font-size:20px}}
input{{width:100%;padding:8px;margin:6px 0 14px;box-sizing:border-box;border:1px solid #ccc}}
.button{{background:#0073aa;color:#fff;border:none;padding:10px 20px;width:100%;cursor:pointer}}
</style></head>
<body>
<div id="login">
<h1>WordPress</h1>
<form method="POST">
<label>Username</label><input name="log" type="text"/>
<label>Password</label><input name="pwd" type="password"/>
<input class="button" type="submit" value="Log In"/>
</form>
</div>
</body>
</html>"""

_403 = ("<html><body><h1>403 Forbidden</h1>"
        "<p>You don't have permission to access this resource.</p>"
        "<hr/><i>Apache/2.4.41 (Ubuntu)</i></body></html>")

_404 = ("<html><body><h1>404 Not Found</h1>"
        "<p>The requested URL was not found on this server.</p>"
        "<hr/><i>Apache/2.4.41 (Ubuntu)</i></body></html>")


def _fake_headers(resp: Response) -> Response:
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    return resp


@app.after_request
def _add_headers(resp: Response) -> Response:
    return _fake_headers(resp)


# Root / admin portal
@app.route("/", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/", methods=["GET", "POST"])
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = ""
    if request.method == "POST":
        error = '<p class="err">Invalid username or password.</p>'
    return _LOGIN_PAGE.format(error=error, action=request.path), 200


# phpMyAdmin trap
@app.route("/phpmyadmin", methods=["GET", "POST"])
@app.route("/phpmyadmin/", methods=["GET", "POST"])
@app.route("/pma", methods=["GET", "POST"])
@app.route("/phpMyAdmin", methods=["GET", "POST"])
def phpmyadmin():
    error = ""
    if request.method == "POST":
        error = '<p class="err">Access denied for user.</p>'
    return _LOGIN_PAGE.format(error=error, action=request.path), 200


# WordPress login trap
@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/wp-admin", methods=["GET", "POST"])
def wp_login():
    return _WP_PAGE, 200


# Honey token file downloads
@app.route("/backup/credentials.txt")
@app.route("/admin/credentials.txt")
@app.route("/config/credentials.txt")
def honey_credentials():
    return send_file(str(FAKE_DATA_DIR / "credentials.txt"),
                     mimetype="text/plain",
                     as_attachment=True)


@app.route("/backup/dump.sql")
@app.route("/admin/dump.sql")
def honey_dump():
    return send_file(str(FAKE_DATA_DIR / "dump.sql"),
                     mimetype="text/plain",
                     as_attachment=True)


@app.route("/backup/employees.csv")
@app.route("/admin/employees.csv")
def honey_employees():
    return send_file(str(FAKE_DATA_DIR / "employees.csv"),
                     mimetype="text/csv",
                     as_attachment=True)


# .env file — very commonly probed
@app.route("/.env")
@app.route("/.env.backup")
@app.route("/.env.local")
def dot_env():
    content = (
        "APP_ENV=production\n"
        "APP_KEY=base64:h0n3yp0t==\n"
        f"DB_PASSWORD=S3cr3t!{uuid.uuid4().hex[:8]}\n"
        "MAIL_PASSWORD=smtp_fake_pass\n"
        f"AWS_SECRET_ACCESS_KEY=FAKE{uuid.uuid4().hex.upper()[:32]}\n"
    )
    return Response(content, mimetype="text/plain")


# Common scanner targets that should 403
@app.route("/server-status")
@app.route("/.git/config")
@app.route("/config.php")
@app.route("/wp-config.php")
def forbidden():
    return Response(_403, status=403, mimetype="text/html")


# Catch-all 404
@app.errorhandler(404)
def not_found(e):
    return Response(_404, status=404, mimetype="text/html")


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP Honeypot")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    print(f"[http] Listening on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
