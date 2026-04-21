"""
Insecure JWT Validation — vulnerable and secure variants, side by side.

Scenario: a FastAPI dependency that extracts the current user from an
incoming `Authorization: Bearer <jwt>` header. This is the
authentication function every other handler depends on. Getting it
wrong is a full-compromise bug.

Two real-world failure modes are shown:

  1. `algorithms=["none"]` or missing algorithm pin — attacker replaces
     the signature with an empty string and sets `alg: none`, bypassing
     signature verification entirely. Still observed in the wild in
     2026; the PyJWT maintainers had to add active defenses because of
     how often it was misused.

  2. No expiry check. Token issued months ago is still valid.

  3. HS256 with a shared secret from an env var that was leaked in a
     prior git commit. The attacker forges tokens offline.

The secure version pins the algorithm, validates every claim, rejects
expired tokens, and uses an asymmetric algorithm (RS256) with a public
key so even a compromised application server cannot mint new tokens.
"""

import os
import time

import jwt  # PyJWT
from jwt import ExpiredSignatureError, InvalidTokenError


EXPECTED_ISSUER = "https://auth.example.com/"
EXPECTED_AUDIENCE = "api.example.com"


# ---------------------------------------------------------------------------
# VULNERABLE: accepts alg=none, no expiry check, trusts arbitrary claims.
# ---------------------------------------------------------------------------
def current_user_vulnerable(token: str) -> dict:
    """
    Exploit A — alg=none:

        Take any JWT with a known payload structure, base64-decode it,
        modify the payload to your target user, re-encode, then send as:

            <header_with_alg_none>.<forged_payload>.

        PyJWT accepts it because `algorithms` is None, so every alg is
        allowed — including "none", which skips signature verification.

    Exploit B — signature-skip option:

        options={"verify_signature": False} is here for a "debugging"
        reason a junior dev added during an incident and never removed.
        It means every signed or unsigned token is trusted.

    Exploit C — no expiry:

        A token issued 18 months ago during pen testing is still valid
        because `verify_exp` was never turned on. Any captured token
        becomes a perpetual credential.
    """
    payload = jwt.decode(
        token,
        # Note: no key passed, because verify_signature is off.
        options={"verify_signature": False, "verify_exp": False},
    )
    return {
        "user_id": payload["sub"],
        "role": payload.get("role", "user"),  # fully attacker-controlled
        "tenant_id": payload.get("tenant_id"),
    }


# ---------------------------------------------------------------------------
# SECURE: pinned algorithm, asymmetric key, explicit claim validation.
# ---------------------------------------------------------------------------
def _load_public_key() -> str:
    """
    In production: load from JWKS and cache per `kid`. For brevity this
    example reads from an env var populated at container start.
    """
    pem = os.environ.get("JWT_PUBLIC_KEY_PEM")
    if not pem:
        raise RuntimeError("JWT_PUBLIC_KEY_PEM is required")
    return pem


def current_user_secure(token: str) -> dict:
    """
    Properties of this function, each tied to a specific failure mode:

      - `algorithms=["RS256"]` — explicit allowlist. alg=none is
        rejected. Algorithm-confusion (RS256-as-HS256) is rejected
        because HS256 is not in the list.

      - `key=<public_key>` — asymmetric key. Even if this process is
        compromised, the attacker cannot mint new tokens without the
        private key, which lives in the authorization server.

      - `options={"require": [...]}` — required claims must be present.
        Missing `exp` is a token we reject, not a token we treat as
        eternal.

      - `verify_iss`, `verify_aud` — prevent a token issued for a
        different audience (e.g., the consumer app's token) from being
        accepted by this service.

      - `leeway=30` — 30-second clock skew tolerance. Without this you
        get intermittent failures during real clock drift; with a much
        larger value you give attackers a longer replay window.

      - Claim whitelist on the return — we build our user object from
        only the claims we validated. We do not echo arbitrary claims
        back to the rest of the application.
    """
    try:
        payload = jwt.decode(
            token,
            _load_public_key(),
            algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            leeway=30,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except ExpiredSignatureError:
        raise PermissionError("token expired") from None
    except InvalidTokenError as e:
        # Intentionally do not echo the underlying error to the client;
        # log it with a request ID and return a generic 401.
        raise PermissionError("invalid token") from e

    # Minimal, validated user record. `role` is fetched fresh from the
    # authorization service for high-privilege operations; the JWT
    # claim is only used for low-sensitivity routing.
    return {
        "user_id": payload["sub"],
        "role": payload.get("role", "user"),
        "tenant_id": payload.get("tenant_id"),
        "issued_at": payload["iat"],
        "expires_at": payload["exp"],
    }


# ---------------------------------------------------------------------------
# A lightweight test harness. Run this file to see the vulnerable
# version accept a forged token that the secure version rejects.
# ---------------------------------------------------------------------------
def _demo():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Generate a keypair just for the demo.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    os.environ["JWT_PUBLIC_KEY_PEM"] = public_pem

    now = int(time.time())

    # A legitimately-signed token.
    good_token = jwt.encode(
        {
            "sub": "user-123", "role": "user", "tenant_id": "t-1",
            "iss": EXPECTED_ISSUER, "aud": EXPECTED_AUDIENCE,
            "iat": now, "exp": now + 900,
        },
        private_pem, algorithm="RS256",
    )

    # A forged "alg=none" token with admin role.
    import base64, json
    def b64(x):
        return base64.urlsafe_b64encode(
            json.dumps(x, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
    forged_token = (
        b64({"typ": "JWT", "alg": "none"}) + "."
        + b64({"sub": "attacker", "role": "admin", "tenant_id": "t-1",
               "iss": EXPECTED_ISSUER, "aud": EXPECTED_AUDIENCE,
               "iat": now - 3600, "exp": now - 60})
        + "."
    )

    # Vulnerable accepts the forgery AND the expired forged token.
    print("VULNERABLE (forged):", current_user_vulnerable(forged_token))
    # → {'user_id': 'attacker', 'role': 'admin', ...}

    # Secure rejects the forgery.
    try:
        current_user_secure(forged_token)
    except PermissionError as e:
        print("SECURE (forged):    rejected —", e)

    # Both accept the good token.
    print("VULNERABLE (good):  ", current_user_vulnerable(good_token))
    print("SECURE (good):      ", current_user_secure(good_token))


if __name__ == "__main__":
    _demo()
