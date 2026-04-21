"""
Hardened counterpart to app.py.

Every endpoint from app.py is implemented here with the vulnerability removed.
Read the two files side-by-side to see the exact shape of each fix. This is
what the pipeline should eventually flag as clean (modulo dependency CVEs,
which the SCA tools handle separately).
"""

import hashlib  # noqa: F401 — kept so the import delta with app.py is obvious
import ipaddress
import logging
import os
import subprocess
from functools import wraps
from urllib.parse import urlparse

import bcrypt
import jwt
import requests
from flask import Flask, Response, jsonify, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import BaseModel, ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

app = Flask(__name__)
log = logging.getLogger("secure-demo")

# FIX: hardcoded-secret → environment-sourced. Boot fails if unset, which is
# the correct behavior — silent fallbacks to "" let bad builds reach prod.
JWT_SECRET = os.environ["JWT_SECRET"]

# FIX: missing-rate-limiting → Flask-Limiter with a conservative default. Per-
# route overrides are applied where the blast radius warrants a tighter cap.
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60/minute"],
    storage_uri="memory://",
)

# FIX: ssrf → explicit allowlist, populated from env and normalized once.
ALLOWED_FETCH_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("FETCH_ALLOWLIST", "").split(",")
    if h.strip()
}

# FIX: path-traversal → canonicalize the upload root once, prefix-check every
# target against it. Trailing-separator check avoids the `/var/app/uploads2`
# bypass that a naive `startswith` allows.
UPLOAD_ROOT = os.path.realpath("/var/app/uploads")

engine: Engine = create_engine("sqlite:///:memory:")
with engine.begin() as conn:
    conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"))
    conn.execute(text("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com')"))
    conn.execute(text("INSERT INTO users (username, email) VALUES ('bob',   'bob@example.com')"))


def require_admin(f):
    """FIX: missing-authentication → bearer JWT required, admin role enforced."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        try:
            claims = jwt.decode(
                auth[7:],
                JWT_SECRET,
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.InvalidTokenError:
            return jsonify({"error": "unauthorized"}), 401
        if "admin" not in claims.get("roles", []):
            return jsonify({"error": "forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper


@app.route("/users")
def get_users():
    """FIX: sql-injection → parameterized query via bound placeholder."""
    username = request.args.get("username", "")
    stmt = text("SELECT id, username, email FROM users WHERE username = :u")
    with engine.connect() as conn:
        rows = conn.execute(stmt, {"u": username}).mappings().all()
    return jsonify([dict(r) for r in rows])


@app.route("/admin")
@require_admin
@limiter.limit("10/minute")
def admin_panel():
    return jsonify({"users": ["alice", "bob"]})


@app.route("/ping")
@limiter.limit("5/minute")
def ping():
    """FIX: command-injection → reject non-IP input, use argv list, no shell."""
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return jsonify({"error": "invalid host"}), 400
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,
        check=False,
    )
    return result.stdout


class LoadRequest(BaseModel):
    """FIX: insecure-deserialization → a strict schema over JSON, no pickle."""
    kind: str
    value: str | int | float | bool


@app.route("/load", methods=["POST"])
def load_object():
    try:
        data = LoadRequest.model_validate_json(request.get_data())
    except ValidationError as e:
        return jsonify({"error": "invalid payload", "details": e.errors()}), 400
    return jsonify({"type": data.kind, "repr": repr(data.value)})


@app.route("/fetch")
@limiter.limit("20/minute")
def fetch_url():
    """FIX: ssrf → scheme check, hostname allowlist, no redirects followed."""
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "scheme not allowed"}), 400
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_FETCH_HOSTS:
        return jsonify({"error": "host not on allowlist"}), 400
    try:
        r = requests.get(url, timeout=5, allow_redirects=False)
    except requests.RequestException:
        return jsonify({"error": "fetch failed"}), 502
    return jsonify({"status": r.status_code, "body": r.text[:200]})


@app.route("/hash", methods=["POST"])
@limiter.limit("10/minute")
def hash_password():
    """FIX: weak-crypto → bcrypt with a work factor appropriate for a web tier."""
    password = (request.json or {}).get("password", "").encode()
    if not password:
        return jsonify({"error": "password required"}), 400
    digest = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
    return jsonify({"hash": digest.decode()})


@app.route("/file")
def read_file():
    """FIX: path-traversal → canonicalize, prefix-check against upload root."""
    name = request.args.get("name", "")
    target = os.path.realpath(os.path.join(UPLOAD_ROOT, name))
    if not (target == UPLOAD_ROOT or target.startswith(UPLOAD_ROOT + os.sep)):
        return jsonify({"error": "forbidden"}), 403
    if not os.path.isfile(target):
        return jsonify({"error": "not found"}), 404
    return send_file(target)


@app.route("/token")
def issue_token():
    token = jwt.encode({"sub": "demo-user"}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.after_request
def set_security_headers(resp: Response) -> Response:
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


if __name__ == "__main__":
    # FIX: debug-mode-enabled → debug off, bound to loopback for dev only.
    # Production deployment uses a real WSGI server behind a reverse proxy.
    app.run(host="127.0.0.1", port=5000, debug=False)
