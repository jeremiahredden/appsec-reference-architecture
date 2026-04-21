"""
Hardcoded Secrets — vulnerable and secure patterns, side by side.

Scenario: a notification service that posts messages to a third-party
vendor and reads customer records from a database. It needs two
credentials: the vendor API key and a database password.

The vulnerable version is the pattern secret-scanners catch ~every
week in real repos. The secure version demonstrates the progression
most teams go through: env vars for local dev, a real secrets manager
in production, with a single `get_secret()` abstraction so code does
not care which environment it is running in.

Important: if you find hardcoded credentials during a review, they are
compromised. git history preserves them forever. Removing the line is
not a fix — rotate the secret at the source of truth.
"""

import os
from functools import lru_cache
from typing import Optional

import requests


# =============================================================================
# VULNERABLE — do not do any of this.
# =============================================================================

# Problem 1: credentials in source. Visible to anyone with read access
# to the repo (including every employee, every CI runner, every LLM
# that indexed it). Lives in git history forever — `git rm` does not
# remove it from the log.
VENDOR_API_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY

# Problem 2: password embedded in a connection string, committed.
DATABASE_URL = "postgresql://svc_notify:S3cretP@ssw0rd@prod-db.internal:5432/notifications"

# Problem 3: a "real-looking fallback" in env-var defaults. Looks like
# defensive coding; actually a hardcoded credential that kicks in if
# the env var is missing.
SLACK_WEBHOOK = os.environ.get(
    "SLACK_WEBHOOK",
    "https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL
)


def send_notification_vulnerable(message: str) -> None:
    requests.post(
        "https://api.notify.example.com/v1/send",
        json={"msg": message},
        headers={"Authorization": f"Bearer {VENDOR_API_KEY}"},
        timeout=5,
    )


# =============================================================================
# SECURE — single abstraction, fail-fast on startup, prod uses a KMS-
# backed secrets manager, dev uses environment variables.
# =============================================================================


class SecretsProvider:
    """
    One interface over local env vars and cloud secrets managers. The
    abstraction lets application code call `secrets.get("vendor_api_key")`
    without caring whether we are in dev, staging, or prod.

    Two properties of this design that matter for review:

      - `lru_cache` on the fetch — secrets managers charge per call
        and have rate limits. Cache per process.

      - No default values. If the secret is missing we raise, loud and
        early, at application startup. A silent fallback to "" or to a
        placeholder string hides configuration bugs until they become
        incidents.
    """

    def __init__(self, environment: Optional[str] = None):
        self.environment = environment or os.environ.get("ENV", "development")
        self._client = None
        if self.environment == "production":
            import boto3  # imported lazily so dev does not need boto3
            self._client = boto3.client("secretsmanager")

    @lru_cache(maxsize=32)
    def get(self, name: str) -> str:
        if self.environment == "production":
            return self._get_from_aws(name)
        return self._get_from_env(name)

    def _get_from_aws(self, name: str) -> str:
        # Secret IDs follow a convention — `/app/<env>/<name>`.
        secret_id = f"/notify/prod/{name}"
        resp = self._client.get_secret_value(SecretId=secret_id)
        value = resp.get("SecretString")
        if not value:
            raise RuntimeError(f"secret {secret_id} is empty or binary")
        return value

    def _get_from_env(self, name: str) -> str:
        # Env var names are upper-snake-case versions of the secret name.
        env_name = name.upper()
        value = os.environ.get(env_name)
        if not value:
            raise RuntimeError(
                f"secret {name} is missing. Set {env_name} in your .env file "
                f"(see .env.example for the required keys)."
            )
        return value


# Instantiate once at module load. Application code takes a dependency
# on the abstraction, not on the underlying provider.
secrets = SecretsProvider()


def send_notification_secure(message: str) -> None:
    # No credential is ever written to source. The key is fetched from
    # Secrets Manager in prod, from the local env in dev, and a missing
    # value fails fast rather than using a placeholder.
    api_key = secrets.get("vendor_api_key")
    requests.post(
        "https://api.notify.example.com/v1/send",
        json={"msg": message},
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=5,
    )


# =============================================================================
# If you inherit a repo with committed secrets, this is the response:
#
#   1. Treat the secret as compromised. Do not "just remove the line."
#   2. Rotate the credential at the source of truth (vendor, database,
#      cloud IAM). The new value goes into Secrets Manager, not the
#      repo.
#   3. Audit usage of the old credential before rotation. You want to
#      know whether it was used from an unexpected source in the log
#      window — that answers "did we get breached via this leak."
#   4. Purge the secret from git history only after rotation. Tools:
#      BFG Repo-Cleaner, git-filter-repo. Force-push with team
#      coordination.
#   5. Add a pre-commit hook (gitleaks, detect-secrets) so the next
#      developer's mistake is caught before it lands.
#
# A checklist without step 1 is a liability — it gives the team a
# false sense of closure while the credential is still live.
# =============================================================================
