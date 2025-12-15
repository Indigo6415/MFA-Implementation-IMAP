import os
import sqlite3
import secrets
import base64
import hashlib
import datetime
from io import BytesIO

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    flash,
)
import pam
import pyotp
import qrcode

# -------------------------------------------------
# Flask application setup
# -------------------------------------------------

app = Flask(__name__)

# Flask session secret
# In production this MUST be provided via environment variable
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_me_in_real_setup")

# Path to the SQLite database
DB_PATH = os.path.join(os.path.dirname(__file__), "mfa.db")


# =================================================
# DATABASE HELPERS
# =================================================

def get_db():
    """
    Open a new SQLite connection.
    A new connection per request avoids cross-thread issues.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def migrate_db():
    """
    Idempotent database migration.

    This function can be executed on every startup:
    - Creates tables if they do not exist
    - Adds missing columns for older database versions
    - Safe to run multiple times
    """
    conn = get_db()
    c = conn.cursor()

    # -------------------------------------------------
    # users table
    # -------------------------------------------------
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            mfa_secret TEXT,
            app_password TEXT,
            mfa_initialized INTEGER DEFAULT 0
        )
    """)

    # Add mfa_initialized column if missing (older DBs)
    try:
        c.execute("ALTER TABLE users ADD COLUMN mfa_initialized INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    # -------------------------------------------------
    # app_passwords table
    # -------------------------------------------------
    c.execute("""
        CREATE TABLE IF NOT EXISTS app_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            grace_until TEXT
        )
    """)

    # Index for faster lookups by username
    c.execute("CREATE INDEX IF NOT EXISTS idx_app_pw_user ON app_passwords(username)")

    # Backwards compatibility: add missing columns if needed
    try:
        c.execute("ALTER TABLE app_passwords ADD COLUMN used_at TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        c.execute("ALTER TABLE app_passwords ADD COLUMN grace_until TEXT")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def get_user(username):
    """
    Retrieve a user record from the users table.
    Returns None if the user does not exist.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row


# =================================================
# PASSWORD / MFA HELPERS
# =================================================

def hash_password(pw: str, iterations: int = 200_000) -> str:
    """
    Hash an app-password using PBKDF2-HMAC-SHA256.

    Stored format:
        pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>

    App-passwords are NEVER stored in plaintext.
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode(),
    )


def set_app_password(username, app_password):
    """
    Store a newly generated app-password.

    - Password is stored only as a hash
    - Expiration is fixed at 24 hours
    - used_at and grace_until are set later by dovecot_checkpw
    """
    pw_hash = hash_password(app_password)
    expires_at = (
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    c = conn.cursor()

    # Ensure user exists and mark MFA as initialized
    c.execute("""
        INSERT INTO users (username, mfa_secret, app_password, mfa_initialized)
        VALUES (?, '', '', 1)
        ON CONFLICT(username) DO UPDATE SET mfa_initialized=1
    """, (username,))

    # Insert new app-password record
    c.execute("""
        INSERT INTO app_passwords (username, password_hash, expires_at)
        VALUES (?, ?, ?)
    """, (username, pw_hash, expires_at))

    conn.commit()
    conn.close()


def get_or_create_secret(username):
    """
    Retrieve an existing TOTP secret for a user,
    or generate and store a new one if none exists.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if row and row["mfa_secret"]:
        secret = row["mfa_secret"]
    else:
        secret = pyotp.random_base32()
        c.execute("""
            INSERT INTO users (username, mfa_secret, app_password, mfa_initialized)
            VALUES (?, ?, '', 0)
            ON CONFLICT(username) DO UPDATE SET mfa_secret=excluded.mfa_secret
        """, (username, secret))
        conn.commit()

    conn.close()
    return secret


def get_secret(username):
    """
    Return the TOTP secret for a user, or None if not set.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row["mfa_secret"] if row and row["mfa_secret"] else None


def mark_mfa_initialized(username):
    """
    Mark MFA as initialized for a user.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET mfa_initialized = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


# =================================================
# QR CODE GENERATION
# =================================================

def generate_qr_code(secret, username):
    """
    Generate a base64-encoded PNG QR code for TOTP enrollment.
    Compatible with Microsoft Authenticator and Google Authenticator.
    """
    issuer = "MFA-Portal"
    otp_uri = (
        f"otpauth://totp/{issuer}:{username}"
        f"?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )

    qr = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


# =================================================
# ROUTES
# =================================================

@app.route("/", methods=["GET", "POST"])
def login():
    """
    Primary login endpoint.

    Flow:
    1. Authenticate user via PAM (system credentials)
    2. If MFA already initialized → redirect to MFA challenge
    3. Otherwise → show MFA enrollment QR code
    """
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Vul zowel gebruikersnaam als wachtwoord in.", "error")
            return redirect(url_for("login"))

        p = pam.pam()
        if p.authenticate(username, password):
            session["username"] = username

            user = get_user(username)
            if user and user["mfa_initialized"] == 1 and user["mfa_secret"]:
                return redirect(url_for("mfa_challenge"))

            secret = get_or_create_secret(username)
            qr = generate_qr_code(secret, username)
            return render_template(
                "mfa.html",
                mode="init",
                secret=secret,
                qr=qr,
                username=username,
            )

        flash("Ongeldige gebruikersnaam of wachtwoord.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/mfa", methods=["GET", "POST"])
def mfa_challenge():
    """
    MFA challenge endpoint.

    - Verifies TOTP code
    - On success: generates a one-time app-password
    """
    username = session.get("username")
    if not username:
        flash("Je sessie is verlopen. Log opnieuw in.", "error")
        return redirect(url_for("login"))

    user = get_user(username)
    secret = get_secret(username) or get_or_create_secret(username)

    if request.method == "POST":
        code = request.form.get("code") or ""
        totp = pyotp.TOTP(secret)

        if totp.verify(code):
            app_password = secrets.token_urlsafe(16)
            set_app_password(username, app_password)

            if not user or user["mfa_initialized"] != 1:
                mark_mfa_initialized(username)

            return render_template(
                "result.html",
                app_password=app_password,
                username=username,
            )

        flash("Ongeldige of verlopen code. Probeer het opnieuw.", "error")
        return redirect(url_for("mfa_challenge"))

    return render_template("mfa.html", mode="challenge", username=username)


# =================================================
# APPLICATION ENTRYPOINT
# =================================================

if __name__ == "__main__":
    migrate_db()
    app.run(host="0.0.0.0", port=5000, debug=True)