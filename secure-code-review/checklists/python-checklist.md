# Python Secure Code Review Checklist

Language-specific checklist for reviewing Python code. Each section has three parts: **what to look for**, a **vulnerable** snippet, and the **secure** version. Use this alongside the generic review process guide in the parent folder.

Targeted at the 3.11+ ecosystem: CPython standard library, FastAPI/Flask/Django, SQLAlchemy, `requests`, `httpx`, `cryptography`, `PyJWT`, `pydantic`. Assumes mypy or pyright is in the pipeline and that basic linting (ruff) is already passing.

---

## 1. SQL and NoSQL Injection

**What to look for.** Any string formatting, f-strings, `%` interpolation, or `.format()` being used to build a SQL query. Any code that passes user input directly into a `raw()` / `execute()` / `text()` call. With NoSQL (MongoDB, etc.), any pattern that allows operator injection via a dict whose keys come from user input.

**Vulnerable.**
```python
# Raw string formatting into a SQL query — classic SQLi.
def get_user_by_email(conn, email: str):
    query = f"SELECT id, email, role FROM users WHERE email = '{email}'"
    return conn.execute(query).fetchone()

# SQLAlchemy text() with string interpolation — also vulnerable.
def search_orders(session, customer_name: str):
    return session.execute(
        text(f"SELECT * FROM orders WHERE customer = '{customer_name}'")
    ).fetchall()
```

**Secure.**
```python
from sqlalchemy import text

# Parameterized query via the DB-API — driver handles escaping.
def get_user_by_email(conn, email: str):
    query = "SELECT id, email, role FROM users WHERE email = %s"
    return conn.execute(query, (email,)).fetchone()

# SQLAlchemy with named parameters — never interpolate into text().
def search_orders(session, customer_name: str):
    return session.execute(
        text("SELECT * FROM orders WHERE customer = :name"),
        {"name": customer_name},
    ).fetchall()

# Or, preferred: use the ORM, which parameterizes by default.
def search_orders_orm(session, customer_name: str):
    return session.query(Order).filter(Order.customer == customer_name).all()
```

---

## 2. Command Injection

**What to look for.** `subprocess.run`, `subprocess.Popen`, `subprocess.call`, or `os.system` invoked with `shell=True` and any user-controlled input. Also watch for string formatting that builds a shell command and then invokes it.

**Vulnerable.**
```python
import subprocess

def convert_image(filename: str):
    # User controls `filename`; shell metacharacters give an attacker RCE.
    # Payload: "photo.png; rm -rf /"
    subprocess.run(f"convert {filename} output.jpg", shell=True, check=True)
```

**Secure.**
```python
import subprocess
import shlex
from pathlib import Path

def convert_image(filename: str):
    # Validate filename against an allowlist.
    path = Path(filename).resolve()
    uploads_dir = Path("/srv/uploads").resolve()
    if uploads_dir not in path.parents:
        raise ValueError("filename must be inside uploads directory")

    # Pass args as a list — no shell interpretation.
    subprocess.run(
        ["convert", str(path), "output.jpg"],
        shell=False,
        check=True,
        timeout=30,
    )
```

---

## 3. Path Traversal

**What to look for.** `os.path.join(base_dir, user_input)` or `Path(base) / user_input` without post-join validation. `open(user_input)` anywhere. Any code that constructs a file path from untrusted data.

**Vulnerable.**
```python
from pathlib import Path

def read_user_file(uploads_dir: str, filename: str) -> bytes:
    # Attacker supplies "../../../etc/passwd" and escapes uploads_dir.
    return (Path(uploads_dir) / filename).read_bytes()
```

**Secure.**
```python
from pathlib import Path

def read_user_file(uploads_dir: str, filename: str) -> bytes:
    base = Path(uploads_dir).resolve(strict=True)
    target = (base / filename).resolve()
    # Reject any path that resolves outside the uploads directory.
    if base not in target.parents and target != base:
        raise ValueError("path traversal detected")
    if not target.is_file():
        raise FileNotFoundError(filename)
    return target.read_bytes()
```

---

## 4. Insecure Deserialization

**What to look for.** `pickle.loads`, `pickle.load`, `yaml.load` without `SafeLoader`, `marshal.loads`, `shelve`, `dill`, any use of `jsonpickle`. If any of these touch data that could be attacker-controlled — including cache values, cookies, queue messages, uploaded files — it is a Critical finding.

**Vulnerable.**
```python
import pickle
import base64

def load_session(cookie_value: str):
    # pickle.loads on any attacker-controlled bytes is RCE.
    raw = base64.b64decode(cookie_value)
    return pickle.loads(raw)
```

**Secure.**
```python
import json
from pydantic import BaseModel, Field

class Session(BaseModel):
    user_id: str = Field(min_length=1, max_length=64)
    issued_at: int
    expires_at: int

def load_session(cookie_value: str) -> Session:
    # Parse as JSON (no code execution), then validate with a typed schema.
    data = json.loads(cookie_value)
    return Session.model_validate(data)
```

If the cookie must be tamper-resistant, sign it server-side (HMAC with a KMS-managed key) and verify the signature *before* deserializing. Encode with JSON, never pickle.

---

## 5. Secrets Management

**What to look for.** Literal strings that look like API keys, passwords, connection strings, or tokens. `os.environ.get("X", "fallback-real-looking-value")` with a real default. Commented-out credentials. Secrets in test fixtures. Connection strings with embedded passwords in config files that are committed.

**Vulnerable.**
```python
# Hardcoded credentials — visible in git history forever, even after removal.
API_KEY = "sk-live-b8f1c2d0a9e84f3c9a1b5d7e2f6c8a0b"
DATABASE_URL = "postgresql://admin:S3cretP@ss@prod-db.internal:5432/app"

def send_notification(message: str):
    requests.post(
        "https://api.notify.example.com/v1/send",
        json={"msg": message},
        headers={"Authorization": f"Bearer {API_KEY}"},
    )
```

**Secure.**
```python
import os
import boto3
from functools import lru_cache

@lru_cache(maxsize=1)
def get_api_key() -> str:
    """
    Fetch from AWS Secrets Manager in prod, environment in dev.
    Cached because the function is called on every request path.
    """
    if os.environ.get("ENV") == "production":
        client = boto3.client("secretsmanager")
        resp = client.get_secret_value(SecretId="notify/api-key")
        return resp["SecretString"]
    # Local/dev: fail loudly if the env var is missing.
    key = os.environ.get("NOTIFY_API_KEY")
    if not key:
        raise RuntimeError("NOTIFY_API_KEY is required in non-prod envs")
    return key

def send_notification(message: str):
    requests.post(
        "https://api.notify.example.com/v1/send",
        json={"msg": message},
        headers={"Authorization": f"Bearer {get_api_key()}"},
        timeout=5,
    )
```

If you find hardcoded credentials during review: they are compromised. Treat them as leaked — rotate the secret, do not just remove the line from the file. Git history remembers.

---

## 6. Weak Cryptography

**What to look for.** `hashlib.md5`, `hashlib.sha1` for anything that protects confidentiality, integrity, or a secret. Password hashing via any `hashlib` function (these are fast hashes; password hashing must be slow). `random.random`, `random.randint`, `random.choice` for security-sensitive values. AES in ECB mode. Custom MAC construction.

**Vulnerable.**
```python
import hashlib
import random
import string

def hash_password(password: str) -> str:
    # SHA-256 is fast — a GPU rig cracks millions/sec.
    return hashlib.sha256(password.encode()).hexdigest()

def generate_reset_token(length: int = 32) -> str:
    # random.choices is a Mersenne Twister — state recoverable from output.
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=length))
```

**Secure.**
```python
import secrets
from argon2 import PasswordHasher, exceptions as argon2_exc

# Tuned for ~50ms on target hardware; revisit annually.
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def hash_password(password: str) -> str:
    return _ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except argon2_exc.VerifyMismatchError:
        return False

def generate_reset_token() -> str:
    # 32 bytes → 256 bits of entropy, URL-safe.
    return secrets.token_urlsafe(32)
```

---

## 7. XML External Entity (XXE)

**What to look for.** `xml.etree.ElementTree.parse`, `lxml.etree.parse`, or any XML parser invoked on untrusted XML without disabling DTD loading and entity resolution. SOAP endpoints and legacy integrations are the common sources.

**Vulnerable.**
```python
from lxml import etree

def parse_upload(xml_bytes: bytes):
    # Default lxml parser resolves external entities.
    # Payload:
    # <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    # <root>&xxe;</root>
    return etree.fromstring(xml_bytes)
```

**Secure.**
```python
from lxml import etree
from defusedxml.ElementTree import fromstring as safe_fromstring

def parse_upload(xml_bytes: bytes):
    # Option A — explicit parser with DTD/entity loading disabled.
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )
    return etree.fromstring(xml_bytes, parser=parser)

def parse_upload_defused(xml_bytes: bytes):
    # Option B — use defusedxml, which refuses all dangerous constructs.
    return safe_fromstring(xml_bytes)
```

Prefer `defusedxml` for all new code. Document the reason when legacy compatibility requires the explicit `lxml` parser with hardened options.

---

## 8. Server-Side Request Forgery (SSRF)

**What to look for.** `requests.get(url)` where `url` is constructed from user input. `httpx`, `urllib3`, `aiohttp` — same pattern. Image proxies, URL previews, webhook callbacks, "import from URL" features are all SSRF-prone.

**Vulnerable.**
```python
import requests

def fetch_preview(target_url: str) -> bytes:
    # Attacker supplies http://169.254.169.254/latest/meta-data/iam/...
    # to steal AWS credentials from EC2 metadata service.
    return requests.get(target_url, timeout=5).content
```

**Secure.**
```python
import ipaddress
import socket
from urllib.parse import urlparse
import requests

ALLOWED_SCHEMES = {"https"}
ALLOWED_PORTS = {443}

def _is_public_ip(host: str) -> bool:
    # Resolve and check every answer — prevents DNS-rebinding bypass by
    # re-resolving (combined with short-lived session + connect-time check).
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True

def fetch_preview(target_url: str) -> bytes:
    parsed = urlparse(target_url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("only https is allowed")
    if parsed.port and parsed.port not in ALLOWED_PORTS:
        raise ValueError("only port 443 is allowed")
    if not parsed.hostname or not _is_public_ip(parsed.hostname):
        raise ValueError("target resolves to a non-public address")

    # Cap response size; enforce strict timeout.
    resp = requests.get(target_url, timeout=(3, 10), stream=True,
                        allow_redirects=False)
    resp.raise_for_status()
    return resp.raw.read(2 * 1024 * 1024, decode_content=True)
```

For production, put a dedicated egress proxy in front that enforces the allowlist — application-layer checks are a defense-in-depth, not the primary control.

---

## 9. Insecure JWT Handling

**What to look for.** `jwt.decode(token, verify=False)`. `jwt.decode(..., algorithms=None)`. Missing expiry validation. Use of HS256 with a weak or hardcoded secret. JWTs where the code trusts claims it has not validated (especially `role`, `admin`, `tenant_id`).

**Vulnerable.**
```python
import jwt  # PyJWT

def current_user(token: str):
    # options={"verify_signature": False} — trusts whatever the client sent.
    # Also no algorithm pin — accepts "alg": "none".
    payload = jwt.decode(token, options={"verify_signature": False})
    return {"user_id": payload["sub"], "role": payload.get("role", "user")}
```

**Secure.**
```python
import jwt
from jwt import InvalidTokenError, ExpiredSignatureError

EXPECTED_ISSUER = "https://auth.example.com/"
EXPECTED_AUDIENCE = "api.example.com"

def current_user(token: str, jwks_public_key) -> dict:
    try:
        payload = jwt.decode(
            token,
            jwks_public_key,
            algorithms=["RS256"],          # explicit algorithm allowlist
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_signature": True,
            },
        )
    except ExpiredSignatureError:
        raise PermissionError("token expired") from None
    except InvalidTokenError as e:
        raise PermissionError(f"token rejected: {e}") from None

    # Do not trust `role` from the token if authorization requires fresh lookup.
    return {"user_id": payload["sub"], "role": payload.get("role", "user")}
```

---

## 10. Flask and Django Specifics

**What to look for.**

- `app.run(debug=True)` in any file on a deploy path. Werkzeug debugger is an RCE when DEBUG=True and the app is reachable.
- Flask apps with no `Talisman` / explicit security headers.
- Django with `DEBUG = True` in settings reachable by prod.
- `@csrf_exempt` decorators — each one is a finding until justified.
- `ALLOWED_HOSTS = ["*"]` in Django settings.
- Session cookies missing `Secure`, `HttpOnly`, `SameSite`.
- CORS middleware with `allow_origins=["*"]` combined with `allow_credentials=True` — an explicitly dangerous combination.

**Vulnerable (Flask).**
```python
from flask import Flask, request
app = Flask(__name__)

@app.route("/echo", methods=["POST"])
def echo():
    return request.form["text"]  # no CSRF, no auth, no output encoding

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # debugger + RCE if remotely reachable
```

**Secure (Flask).**
```python
from flask import Flask, request
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from markupsafe import escape
import os

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_TIME_LIMIT=3600,
)
CSRFProtect(app)
Talisman(
    app,
    content_security_policy={
        "default-src": "'self'",
        "img-src": ["'self'", "data:"],
        "script-src": "'self'",
    },
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    referrer_policy="strict-origin-when-cross-origin",
)

@app.route("/echo", methods=["POST"])
def echo():
    # CSRF enforced by Flask-WTF; output escaped.
    return escape(request.form.get("text", ""))

# Never call app.run(debug=True) on a deploy path.
# Production: gunicorn + reverse proxy + DEBUG unset.
```

**Vulnerable (Django `settings.py`).**
```python
DEBUG = True
ALLOWED_HOSTS = ["*"]
SECRET_KEY = "insecure-dev-key"
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
```

**Secure (Django `settings.py`).**
```python
import os

DEBUG = os.environ.get("DJANGO_DEBUG") == "1"       # default False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]        # fail fast if missing
ALLOWED_HOSTS = os.environ["DJANGO_ALLOWED_HOSTS"].split(",")

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31_536_000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"
```
