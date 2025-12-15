#!/usr/bin/env python3
import os
import sys
import sqlite3
import datetime
import hashlib
import hmac
import base64
import pwd

DB = "/opt/mfaportal/mfa.db"
GRACE_SECONDS = int(os.environ.get("GRACE_SECONDS", "60"))  # zet op 0 voor strict one-time
DEBUG = os.environ.get("DEBUG_CHECKPW", "0") == "1"


def log(msg: str) -> None:
    if DEBUG:
        print(f"[checkpw] {msg}", file=sys.stderr)


def tempfail() -> None:
    # 111 = tijdelijke failure (Thunderbird ziet dan "temporary auth failure")
    sys.exit(111)


def verify_hash(password: str, stored: str) -> bool:
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
    # Dovecot checkpassword geeft user\0pass\0 op fd 3
    with os.fdopen(3, "rb", closefd=False) as f:
        raw = f.read()
    parts = raw.split(b"\0")
    if len(parts) < 2:
        return ("", "")
    user = parts[0].decode(errors="ignore")
    pw = parts[1].decode(errors="ignore")
    return (user, pw)


def clean(s: str) -> str:
    return s.replace("\t", "").replace("\r", "").replace("\n", "")


def set_env_for_reply(user: str) -> None:
    u = clean(user)
    os.environ["USER"] = u
    try:
        home = pwd.getpwnam(u).pw_dir
    except KeyError:
        sys.exit(1)
    os.environ["HOME"] = clean(home)


def now_utc_str() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def main() -> None:
    if len(sys.argv) < 2:
        tempfail()
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
        log("no input (empty user or pw)")
        sys.exit(1)

    now = now_utc_str()
    log(f"user={user} pw_len={len(pw)} now={now} grace={GRACE_SECONDS}")

    try:
        conn = sqlite3.connect(DB, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        cur = conn.cursor()

        # Let op: we pakken ook gebruikte records i.v.m. grace
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
            if not verify_hash(pw, r["password_hash"]):
                continue

            # MATCH
            used_at = r["used_at"]
            grace_until = r["grace_until"]

            # Eerste succesvolle login: markeer used_at en grace_until (als grace > 0)
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
                if cur.rowcount != 1:
                    sys.exit(1)  # race

                set_env_for_reply(user)
                os.execv(reply_path, [reply_path])

            # Al gebruikt: alleen toestaan binnen grace
            if GRACE_SECONDS > 0 and grace_until is not None:
                cur.execute(
                    "SELECT (grace_until > ?) AS ok FROM app_passwords WHERE id = ?",
                    (now, r["id"]),
                )
                ok = cur.fetchone()[0]
                if ok:
                    set_env_for_reply(user)
                    os.execv(reply_path, [reply_path])

            sys.exit(1)

        sys.exit(1)

    except sqlite3.Error as e:
        log(f"sqlite error: {e!r}")
        tempfail()
    except Exception as e:
        log(f"unexpected: {e!r}")
        tempfail()


if __name__ == "__main__":
    main()