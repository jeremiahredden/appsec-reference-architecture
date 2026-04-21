"""
Insecure Deserialization — vulnerable and secure variants, side by side.

Scenario: a cache layer that stores "user session" objects. The
session is serialized and written to Redis (or to a cookie) and
deserialized on the next request.

The vulnerable version uses `pickle`, which is the canonical Python
deserialization footgun. The secure version replaces `pickle` with
JSON + a pydantic schema — every field is typed, every extra field is
rejected, no code runs during parsing.

Key fact about pickle that reviewers must internalize: `pickle.loads`
is not a parser. It is an instruction stream interpreter, and the
instruction set includes "construct an arbitrary class" and "call an
arbitrary callable." Any attacker-controlled pickle is remote code
execution, full stop. This is not a "depends on the class being
deserialized" bug — it is a property of pickle itself.
"""

import base64
import json
import pickle
from typing import Optional

from pydantic import BaseModel, Field, ValidationError


# =============================================================================
# VULNERABLE — pickle.loads on attacker-controlled bytes.
# =============================================================================


def load_session_vulnerable(cookie_value: str):
    """
    Exploit — a minimal RCE payload generator:

        import pickle, os, base64
        class Pwn:
            def __reduce__(self):
                return (os.system, ("id > /tmp/pwn",))
        payload = base64.b64encode(pickle.dumps(Pwn())).decode()
        # Paste `payload` into a cookie named `session`.
        # The next request to any endpoint that calls this function
        # runs `id > /tmp/pwn` as the web service user.

    __reduce__ is the pickle protocol's hook for "how do I re-create
    this object" — it returns a callable and its arguments. Attackers
    supply `os.system`, `subprocess.Popen`, or more sophisticated
    gadgets that chain imports. The attacker does not need a class in
    your codebase; they can reference stdlib callables like
    os.system, subprocess.check_output, posix.system, etc.

    There is no "safe subset" of pickle. Do not use it on any data
    that an attacker could plausibly influence — cookies, query
    params, file uploads, cache entries, queue messages, or anything
    crossing a trust boundary.
    """
    raw = base64.b64decode(cookie_value)
    return pickle.loads(raw)   # ← full RCE sink


# =============================================================================
# SECURE — JSON + pydantic schema + HMAC for tamper resistance.
# =============================================================================


class Session(BaseModel):
    """
    Strictly-typed session model. pydantic rejects:
      - extra fields (model_config strict),
      - wrong types,
      - values outside the declared constraints.

    No code runs during validation. Even a malicious payload
    containing `{"__class__": "os.system", "args": ["rm -rf /"]}`
    is just unknown keys that get rejected.
    """

    model_config = {"extra": "forbid"}

    user_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    tenant_id: str = Field(min_length=1, max_length=64)
    role: str = Field(pattern=r"^(user|admin|support)$")
    issued_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)


def _hmac_sign(body: bytes, key: bytes) -> bytes:
    """
    Signs the serialized session so the client cannot tamper with it.
    This is defense-in-depth; the primary protection is that we
    validate schema on every load. Signing keeps the integrity check
    cheap and lets us reject junk before parsing.
    """
    import hmac, hashlib
    return hmac.new(key, body, hashlib.sha256).digest()


def _hmac_verify(body: bytes, signature: bytes, key: bytes) -> bool:
    """Constant-time comparison — prevents timing side-channels."""
    import hmac
    return hmac.compare_digest(signature, _hmac_sign(body, key))


def load_session_secure(cookie_value: str, signing_key: bytes) -> Optional[Session]:
    """
    Layers of defense, each catching a different class of attack:

      1. base64 decode — fails on garbage input with a plain exception.

      2. Split into <body>.<signature> — refuses to parse if the
         signature is missing or malformed.

      3. HMAC verify before parsing JSON — rejects any modified
         payload, including payloads crafted to trigger parser bugs.

      4. json.loads — a pure data parser. No classes. No code. No
         hooks. If the body is not valid JSON we get a ValueError.

      5. pydantic Session.model_validate — every field typed,
         constrained, and an extra-field-strict rejection. An attacker
         sending `{"user_id": "a", "role": "admin", "__class__": "..."}`
         fails the extra=forbid check even if the signature happened
         to verify (it won't, because the signer is server-side-only).
    """
    try:
        encoded = cookie_value.encode()
        body_b64, sig_b64 = encoded.split(b".", 1)
        body = base64.urlsafe_b64decode(body_b64)
        signature = base64.urlsafe_b64decode(sig_b64)
    except (ValueError, base64.binascii.Error):
        return None

    if not _hmac_verify(body, signature, signing_key):
        return None

    try:
        data = json.loads(body)
    except ValueError:
        return None

    try:
        return Session.model_validate(data)
    except ValidationError:
        return None


def save_session_secure(session: Session, signing_key: bytes) -> str:
    """Serialize + sign. Mirror of the load function."""
    body = session.model_dump_json().encode()
    signature = _hmac_sign(body, signing_key)
    return (
        base64.urlsafe_b64encode(body).decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(signature).decode().rstrip("=")
    )


# =============================================================================
# Review notes:
#
# - The same reasoning applies to other "rich" deserializers:
#     * yaml.load without SafeLoader — use yaml.safe_load.
#     * marshal.loads — do not use on untrusted data.
#     * jsonpickle — by design reconstructs arbitrary classes; unsafe.
#     * dill — superset of pickle; same risks, larger gadget surface.
#
# - If you MUST use pickle for legitimate reasons (in-process caching
#   of numpy arrays, for example), keep it on bytes that you produce
#   and consume inside a single process. Never cross a trust boundary
#   with it. Never write it to disk where another process could tamper.
#
# - For cookies specifically: prefer signed JWTs (with all the
#   validation from jwt_validation.py) or an opaque session ID whose
#   value is looked up server-side against a session store. Storing
#   complex state in client-held cookies is a design smell even when
#   the serialization is safe.
# =============================================================================
