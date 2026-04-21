"""
Intentionally vulnerable Flask API — pipeline scan target.

EDUCATIONAL USE ONLY. Do not deploy. Do not run against production data.
Every vulnerability below is marked with:
    # VULNERABILITY: <class> — intentional for pipeline demonstration

The secure counterpart for each handler is commented directly below it so a
reader can see the delta without flipping files. See secure_app.py for the
consolidated hardened build the pipeline should eventually flag as clean.
"""

import hashlib
import os
import pickle
import subprocess  # noqa: F401  (used in the commented-out secure version)

import jwt
import requests
from flask import Flask, jsonify, request, send_file
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

app = Flask(__name__)

# VULNERABILITY: hardcoded-secret — intentional for pipeline demonstration
# A weak constant checked into source. Rotates nothing, grants everything.
# Secure counterpart: load from environment, fail fast if missing.
JWT_SECRET = "supersecret123"
# SECURE:
# JWT_SECRET = os.environ["JWT_SECRET"]   # KeyError on boot if unset — exactly what we want.

# In-memory SQLite for demo. The vulnerability is in how queries are built,
# not which database is behind them.
engine: Engine = create_engine("sqlite:///:memory:")
with engine.begin() as conn:
    conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"))
    conn.execute(text("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com')"))
    conn.execute(text("INSERT INTO users (username, email) VALUES ('bob',   'bob@example.com')"))


@app.route("/users")
def get_users():
    # VULNERABILITY: sql-injection — intentional for pipeline demonstration
    # String-formatted into the SQL body. `?username=' OR 1=1 --` dumps the table.
    username = request.args.get("username", "")
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    with engine.connect() as conn:
        rows = conn.execute(text(query)).mappings().all()
    return jsonify([dict(r) for r in rows])

# SECURE:
# @app.route("/users")
# def get_users():
#     username = request.args.get("username", "")
#     stmt = text("SELECT id, username, email FROM users WHERE username = :u")
#     with engine.connect() as conn:
#         rows = conn.execute(stmt, {"u": username}).mappings().all()
#     return jsonify([dict(r) for r in rows])


@app.route("/admin")
def admin_panel():
    # VULNERABILITY: missing-authentication — intentional for pipeline demonstration
    # Administrative surface, no decorator, no token check, no audit.
    return jsonify({"users": ["alice", "bob"], "system_config": {"debug": True}})

# SECURE:
# from functools import wraps
# def require_admin(f):
#     @wraps(f)
#     def wrapper(*args, **kwargs):
#         auth = request.headers.get("Authorization", "")
#         if not auth.startswith("Bearer "):
#             return jsonify({"error": "unauthorized"}), 401
#         try:
#             claims = jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
#         except jwt.InvalidTokenError:
#             return jsonify({"error": "unauthorized"}), 401
#         if "admin" not in claims.get("roles", []):
#             return jsonify({"error": "forbidden"}), 403
#         return f(*args, **kwargs)
#     return wrapper
#
# @app.route("/admin")
# @require_admin
# def admin_panel():
#     return jsonify({"users": ["alice", "bob"]})


@app.route("/ping")
def ping():
    # VULNERABILITY: command-injection — intentional for pipeline demonstration
    # `?host=8.8.8.8; cat /etc/passwd` runs both commands.
    host = request.args.get("host", "127.0.0.1")
    return os.popen(f"ping -c 1 {host}").read()  # nosec - demo

# SECURE:
# import ipaddress
# @app.route("/ping")
# def ping():
#     host = request.args.get("host", "127.0.0.1")
#     try:
#         ipaddress.ip_address(host)   # reject anything that isn't a literal IP
#     except ValueError:
#         return jsonify({"error": "invalid host"}), 400
#     result = subprocess.run(
#         ["ping", "-c", "1", host],
#         capture_output=True, text=True, timeout=5, shell=False,
#     )
#     return result.stdout


@app.route("/load", methods=["POST"])
def load_object():
    # VULNERABILITY: insecure-deserialization — intentional for pipeline demonstration
    # pickle.loads on attacker-controlled bytes is remote code execution.
    payload = request.get_data()
    obj = pickle.loads(payload)  # noqa: S301
    return jsonify({"type": type(obj).__name__, "repr": repr(obj)})

# SECURE:
# from pydantic import BaseModel, ValidationError
# class LoadRequest(BaseModel):
#     kind: str
#     value: str | int | float | bool
# @app.route("/load", methods=["POST"])
# def load_object():
#     try:
#         data = LoadRequest.model_validate_json(request.get_data())
#     except ValidationError as e:
#         return jsonify({"error": "invalid payload", "details": e.errors()}), 400
#     return jsonify({"type": data.kind, "repr": repr(data.value)})


@app.route("/fetch")
def fetch_url():
    # VULNERABILITY: ssrf — intentional for pipeline demonstration
    # No allowlist, no hostname resolution, no scheme check. Hits metadata
    # services, internal admin panels, or http://localhost:<anything>.
    url = request.args.get("url", "")
    r = requests.get(url, timeout=5)
    return jsonify({"status": r.status_code, "body": r.text[:200]})

# SECURE:
# from urllib.parse import urlparse
# ALLOWED_HOSTS = set(os.environ.get("FETCH_ALLOWLIST", "").split(","))
# @app.route("/fetch")
# def fetch_url():
#     url = request.args.get("url", "")
#     parsed = urlparse(url)
#     if parsed.scheme not in ("http", "https"):
#         return jsonify({"error": "scheme not allowed"}), 400
#     if parsed.hostname not in ALLOWED_HOSTS:
#         return jsonify({"error": "host not on allowlist"}), 400
#     r = requests.get(url, timeout=5, allow_redirects=False)
#     return jsonify({"status": r.status_code, "body": r.text[:200]})


@app.route("/hash", methods=["POST"])
def hash_password():
    # VULNERABILITY: weak-crypto — intentional for pipeline demonstration
    # MD5 is not a password hash. Fast + rainbow-table-friendly + collisions.
    password = request.json.get("password", "")
    digest = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"hash": digest})

# SECURE:
# import bcrypt
# @app.route("/hash", methods=["POST"])
# def hash_password():
#     password = request.json.get("password", "").encode()
#     digest = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
#     return jsonify({"hash": digest.decode()})


@app.route("/file")
def read_file():
    # VULNERABILITY: path-traversal — intentional for pipeline demonstration
    # `?name=../../etc/passwd` escapes the intended directory.
    name = request.args.get("name", "")
    path = os.path.join("/var/app/uploads", name)
    return send_file(path)

# SECURE:
# UPLOAD_ROOT = os.path.realpath("/var/app/uploads")
# @app.route("/file")
# def read_file():
#     name = request.args.get("name", "")
#     target = os.path.realpath(os.path.join(UPLOAD_ROOT, name))
#     if not target.startswith(UPLOAD_ROOT + os.sep):
#         return jsonify({"error": "forbidden"}), 403
#     return send_file(target)


@app.route("/token")
def issue_token():
    # Hardcoded secret above is the actual finding; this handler is here so
    # the pipeline sees the secret in real use rather than as a dead constant.
    token = jwt.encode({"sub": "demo-user"}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


# VULNERABILITY: missing-rate-limiting — intentional for pipeline demonstration
# No Flask-Limiter, no reverse-proxy throttle configured here. Every endpoint
# above is unbounded. Fixed in secure_app.py with Flask-Limiter.

if __name__ == "__main__":
    # VULNERABILITY: debug-mode-enabled — intentional for pipeline demonstration
    # debug=True exposes the Werkzeug console — arbitrary code execution to
    # anyone who can reach the port. Custom Semgrep rule
    # `custom-rules.flask-debug-enabled` flags this directly.
    app.run(host="0.0.0.0", port=5000, debug=True)

# SECURE:
# if __name__ == "__main__":
#     app.run(host="127.0.0.1", port=5000, debug=False)
