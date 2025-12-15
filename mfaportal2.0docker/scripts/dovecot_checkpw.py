#!/usr/bin/env python3
"""
Dovecot checkpassword helper.

This script validates one-time / app-specific passwords stored in SQLite.
It supports:
- Expiration timestamps
- Single-use passwords
- A configurable grace period (needed for Thunderbird and similar clients)

Exit codes:
- 0 / exec(reply): authentication success
- 1: authentication failed
- 111: temporary failure (Dovecot will retry / client sees temp error)
"""

import os
import sys
import sqlite3
import datetime
import hashlib
import hmac
import base64
import pwd

# Path to the MFA / app-password database
DB = "/opt/mfaportal/mfa.db"

# Grace period (in seconds) during which a password may be reused
# This is required because some mail clients (e.g. Thunderbird)
# perform multiple login attempts during account setup.
GRACE_SECONDS = int(os.environ.get("GRACE_SECONDS", "60"))

# Enable debug logging to stderr if set
DEBUG = os.environ.get("DEBUG_CHECKPW", "0") == "1"


def log(msg: str) -> None:
    """Write debug output to stderr if DEBUG is enabled."""
    if DEBUG:
        print(f"[checkpw] {msg}", file=sys.stderr)


def tempfail() -> None:
    """
    Exit with code 111, which tells Dovecot this is a temporary failure.
    Mail clients will usually retry authentication later.
    """
    sys.exit(111)


def verify_hash(password: str, stored: str) -> bool:
    """
    Verify a plaintext password against a stored PBKDF2-SHA256 hash.
    Format:
        pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
    """
    try:
        alg, iters, salt_b64, hash_b64 = stored.split("$", 3)
        if alg != "pbkdf2_sha256":
            return False

        iters = int(iters)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)

        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def read_fd3_userpass() -> tuple[str, str]:
    """
    Read username and password from file descriptor 3.

    Dovecot's checkpassword protocol provides:
        user\\0password\\0
    on file descriptor 3 (NOT stdin).
    """
    with os.fdopen(3, "rb", closefd=False) as f:
        raw = f.read()

    parts = raw.split(b"\0")
    if len(parts) < 2:
        return ("", "")

    user = parts[0].decode(errors="ignore")
    pw = parts[1].decode(errors="ignore")
    return (user, pw)


def clean(s: str) -> str:
    """
    Remove characters that are not allowed in checkpassword
    environment variables (tabs, CR, LF).
    """
    return s.replace("\t", "").replace("\r", "").replace("\n", "")


def set_env_for_reply(user: str) -> None:
    """
    Prepare environment variables required by checkpassword-reply.

    Dovecot requires at least:
    - USER
    - HOME

    These must be safe and sanitized.
    """
    u = clean(user)
    os.environ["USER"] = u

    try:
        home = pwd.getpwnam(u).pw_dir
    except KeyError:
        sys.exit(1)

    os.environ["HOME"] = clean(home)


def now_utc_str() -> str:
    """Return the current UTC time as a SQLite-compatible string."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def main() -> None:
    """
    Main authentication logic:
    - Read credentials from fd 3
    - Find valid app-passwords
    - Enforce expiration, single-use, and grace rules
    """
    if len(sys.argv) < 2:
        tempfail()

    # Path to checkpassword-reply binary (provided by Dovecot)
    reply_path = sys.argv[1]
    if not os.path.exists(reply_path):
        tempfail()

    try:
        user, pw = read_fd3_userpass()
    except Exception as e:
        log(f"fd3 read error: {e!r}")
        tempfail()

    user = user.strip()
    if not user or not pw:
        log("no input (empty user or password)")
        sys.exit(1)

    now = now_utc_str()
    log(f"user={user} pw_len={len(pw)} now={now} grace={GRACE_SECONDS}")

    try:
        # Open database with timeout to avoid lock issues
        conn = sqlite3.connect(DB, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        cur = conn.cursor()

        # Select recent, non-expired app-passwords
        cur.execute(
            """
            SELECT id, password_hash, used_at, grace_until
            FROM app_passwords
            WHERE username = ?
              AND expires_at > ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (user, now),
        )
        rows = cur.fetchall()
        log(f"candidates={len(rows)}")

        for r in rows:
            # Password mismatch → try next candidate
            if not verify_hash(pw, r["password_hash"]):
                continue

            used_at = r["used_at"]
            grace_until = r["grace_until"]

            # First successful use of this password
            if used_at is None:
                if GRACE_SECONDS > 0:
                    cur.execute(
                        """
                        UPDATE app_passwords
                        SET used_at = CURRENT_TIMESTAMP,
                            grace_until = datetime('now', ?)
                        WHERE id = ? AND used_at IS NULL
                        """,
                        (f"+{GRACE_SECONDS} seconds", r["id"]),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE app_passwords
                        SET used_at = CURRENT_TIMESTAMP
                        WHERE id = ? AND used_at IS NULL
                        """,
                        (r["id"],),
                    )

                conn.commit()

                # Ensure exactly one row was updated (race protection)
                if cur.rowcount != 1:
                    sys.exit(1)

                set_env_for_reply(user)
                os.execv(reply_path, [reply_path])

            # Password already used: allow reuse only during grace window
            if GRACE_SECONDS > 0 and grace_until is not None:
                cur.execute(
                    "SELECT (grace_until > ?) AS ok FROM app_passwords WHERE id = ?",
                    (now, r["id"]),
                )
                ok = cur.fetchone()[0]
                if ok:
                    set_env_for_reply(user)
                    os.execv(reply_path, [reply_path])

            # Password matched but is no longer valid
            sys.exit(1)

        # No matching password found
        sys.exit(1)

    except sqlite3.Error as e:
        log(f"sqlite error: {e!r}")
        tempfail()
    except Exception as e:
        log(f"unexpected: {e!r}")
        tempfail()


if __name__ == "__main__":
    main()