from flask import Flask, render_template, request, redirect, Response, session
from werkzeug.security import check_password_hash, generate_password_hash
import secrets
import base64
import os
import qrcode
import io
import sqlite3
from contextlib import closing

from mfa import TOTP

app = Flask(__name__)
app.secret_key = os.urandom(24)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "auth.db")
# Authorization codes are short-lived; store them in SQLite as well


def get_db():
    return sqlite3.connect(DB_PATH)


def ensure_mfa_confirmed_column(db):
    cur = db.execute("PRAGMA table_info(mfa_users)")
    columns = [row[1] for row in cur.fetchall()]

    if "mfa_confirmed" not in columns:
        print("[DB] Migrating: adding mfa_confirmed column to mfa_users")
        db.execute(
            "ALTER TABLE mfa_users ADD COLUMN mfa_confirmed INTEGER DEFAULT 0"
        )


def init_db():
    with closing(get_db()) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS mfa_users (
                email TEXT PRIMARY KEY,
                mfa_secret TEXT NOT NULL,
                mfa_digits INTEGER NOT NULL,
                mfa_interval INTEGER NOT NULL
            )
        """)

        ensure_mfa_confirmed_column(db)

        db.execute("""
            CREATE TABLE IF NOT EXISTS issued_tokens (
                access_token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                token_type TEXT NOT NULL,
                expires_in INTEGER NOT NULL,
                scope TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS auth_codes (
                code TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            mfa_secret TEXT,
            mfa_confirmed INTEGER DEFAULT 0
            )
        """)
        
        db.commit()


# Initialize the database
init_db()


def require_admin():
    if not session.get("admin_authenticated"):
        return redirect("/admin/login")


@app.route("/", methods=["GET"])
def service_not_available():
    return "Service not available at this path.", 404


@app.route("/form", methods=["GET", "POST"])
def form_redirect():
    if request.method == "GET":
        email = request.args.get("login_hint", "")
        return render_template("login.html", email=email)

    # Log all incoming arguments for debugging
    form_payload = request.form.to_dict(flat=False)
    query_params = request.args.to_dict(flat=False)
    json_payload = request.get_json(silent=True)

    print("/form request form:", form_payload)
    print("/form request args:", query_params)
    print("/form request json:", json_payload)

    # POST after login form submit
    email = request.form.get("email")

    # 1. Generate one-time code
    code = secrets.token_urlsafe(32)

    # 2. Store it (very important)
    with closing(get_db()) as db:
        db.execute(
            "INSERT INTO auth_codes (code, email, created_at) VALUES (?, ?, strftime('%s','now'))",
            (code, email)
        )
        db.commit()

    # 3. Redirect EXACTLY to https://localhost
    return redirect(f"https://localhost/?code={code}", code=302)


@app.route("/token", methods=["POST"])
def token_endpoint():
    print("Received /token request")

    # Debug logging
    print("/token request form:", request.form.to_dict(flat=False))
    print("/token request args:", request.args.to_dict(flat=False))
    print("/token request json:", request.get_json(silent=True))

    code = request.form.get("code")
    refresh_token = request.form.get("refresh_token")

    # OAuth requires exactly one grant type per request
    if bool(code) == bool(refresh_token):
        return {
            "error": "invalid_request",
            "error_description": "Provide exactly one of 'code' or 'refresh_token'."
        }, 400

    # ------------------------------------------------------------
    # AUTHORIZATION CODE GRANT
    # ------------------------------------------------------------
    if code:
        # Validate the authorization code
        with closing(get_db()) as db:
            cur = db.execute(
                "SELECT email FROM auth_codes WHERE code = ?",
                (code,)
            )
            row = cur.fetchone()

            # If code is invalid
            if not row:
                return {
                    "error": "invalid_grant",
                    "error_description": "Authorization code is invalid or expired."
                }, 400

            email = row[0]

            # One-time use: delete immediately
            db.execute(
                "DELETE FROM auth_codes WHERE code = ?",
                (code,)
            )

            # Generate new tokens
            access_token = secrets.token_urlsafe(32)
            refresh_token = secrets.token_urlsafe(32)

            # Store issued tokens
            db.execute("""
                INSERT INTO issued_tokens
                (access_token, email, refresh_token, token_type, expires_in, scope)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                access_token,
                email,
                refresh_token,
                "Bearer",
                3600,
                "test_mail test_addressbook test_calendar"
            ))

            db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "test_mail test_addressbook test_calendar"
        }, 200

    # ------------------------------------------------------------
    # REFRESH TOKEN GRANT
    # ------------------------------------------------------------
    # Validate the refresh token
    with closing(get_db()) as db:
        cur = db.execute(
            "SELECT email FROM issued_tokens WHERE refresh_token = ?",
            (refresh_token,)
        )
        row = cur.fetchone()

        # If refresh token is invalid
        if not row:
            return {
                "error": "invalid_grant",
                "error_description": "Refresh token is invalid."
            }, 400

        # Get associated email & generate new access token
        email = row[0]
        access_token = secrets.token_urlsafe(32)

        # Store new access token
        db.execute("""
            INSERT INTO issued_tokens
            (access_token, email, refresh_token, token_type, expires_in, scope)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            access_token,
            email,
            refresh_token,
            "Bearer",
            3600,
            "test_mail test_addressbook test_calendar"
        ))

        db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "test_mail test_addressbook test_calendar"
    }, 200


@app.route("/token/verify", methods=["POST"])
def token_verify_endpoint():
    print("Received /token/verify request")

    access_token = request.form.get("token")

    with closing(get_db()) as db:
        cur = db.execute("""
            SELECT email, scope, expires_in, token_type
            FROM issued_tokens
            WHERE access_token = ?
        """, (access_token,))
        row = cur.fetchone()

    if row:
        email, scope, expires_in, token_type = row
        print("Valid access token received for email:", email)
        return {
            "active": True,
            "email": email,
            "scope": scope,
            "exp": expires_in,
            "token_type": token_type
        }, 200
    else:
        return {
            "active": False,
            "error": "invalid_token",
            "error_description": "The provided access token is invalid or has expired."
        }, 400


@app.route("/.well-known/autoconfig/mail/config-v1.1.xml", methods=["GET"])
def well_known():
    # Extract the email and domain from query parameters if available
    email = request.args.get("emailaddress", "")
    domain = email.split("@")[-1] if email else ""

    return render_template(
        "config-v1.1.xml",
        email=email,
        domain=domain,
    ), 200, {
        "Content-Type": "application/xml"
    }


@app.route("/mfa/user", methods=["POST"])
def mfa_user_endpoint():
    email = request.form.get("email")

    if not email:
        return {"error": "email_required"}, 400

    with closing(get_db()) as db:
        cur = db.execute("""
            SELECT mfa_confirmed
            FROM mfa_users
            WHERE email = ?
        """, (email,))
        row = cur.fetchone()

    # No MFA-record → MFA not enrolled yet
    if not row:
        print(f"[MFA] {email}: no MFA enrollment")
        return {
            "mfa_status": "none"
        }, 200

    mfa_confirmed = row[0]

    # Secret exists, but isn't confirmed yet
    if mfa_confirmed == 0:
        print(f"[MFA] {email}: enrollment pending")
        return {
            "mfa_status": "pending"
        }, 200

    # MFA is active
    print(f"[MFA] {email}: MFA active")
    return {
        "mfa_status": "active"
    }, 200


@app.route("/mfa/register", methods=["POST"])
def mfa_register_endpoint():
    email = request.form.get("email")

    secret = os.urandom(20)
    secret_b32 = base64.b32encode(secret).decode("utf-8")

    with closing(get_db()) as db:
        db.execute("""
            INSERT OR REPLACE INTO mfa_users
            (email, mfa_secret, mfa_digits, mfa_interval, mfa_confirmed)
            VALUES (?, ?, ?, ?, 0)
        """, (email, secret_b32, 6, 30))
        db.commit()

    print(f"Registered MFA for user {email} with secret {secret_b32}")

    otp_url = TOTP(secret_b32).generate_otp_url("MFAPortal", email)

    return {"otp_url": otp_url}, 200


@app.route("/mfa/qr", methods=["GET"])
def mfa_qr_endpoint():
    email = request.args.get("email")

    if not email:
        return {"error": "email_required"}, 400

    with closing(get_db()) as db:
        cur = db.execute("""
            SELECT mfa_secret, mfa_digits, mfa_interval, mfa_confirmed
            FROM mfa_users
            WHERE email = ?
        """, (email,))
        row = cur.fetchone()

    if not row:
        return {"error": "MFA not registered"}, 400

    mfa_secret, digits, interval, confirmed = row

    # QR only shows while enrolling..
    if confirmed == 1:
        return {"error": "MFA already confirmed"}, 403

    totp = TOTP(mfa_secret)
    otp_url = totp.generate_otp_url("MFAPortal", email)

    img = qrcode.make(otp_url)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return Response(
        buf.getvalue(),
        mimetype="image/png",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
        }
    )


@app.route("/mfa/verify", methods=["POST"])
def mfa_verify_endpoint():
    email = request.form.get("email")
    mfa_code = request.form.get("mfa_code")

    with closing(get_db()) as db:
        cur = db.execute("""
            SELECT mfa_secret FROM mfa_users WHERE email = ?
        """, (email,))
        row = cur.fetchone()

    if not row:
        print(f"No MFA enrollment found for {email}")
        return {"mfa_verified": False}, 200

    secret_b32 = row[0]
    totp = TOTP(secret_b32)

    if totp.verify(mfa_code):
        with closing(get_db()) as db:
            db.execute("""
                UPDATE mfa_users
                SET mfa_confirmed = 1
                WHERE email = ?
            """, (email,))
            db.commit()

        print(f"MFA verification successful for user {email}")
        return {"mfa_verified": True}, 200
    else:
        print(f"MFA verification failed for user {email}")
        return {"mfa_verified": False}, 200


# ------------------------------------------------------------
# Administrator panel - admin authentication
# ------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    with closing(get_db()) as db:
        cur = db.execute("""
            SELECT password_hash
            FROM admin_users
            WHERE username = ?
        """, (username,))
        row = cur.fetchone()

    if not row or not check_password_hash(row[0], password):
        return render_template(
            "admin_login.html",
            error="Invalid credentials"
        )

    # Password correct → MFA step
    session["admin_pending"] = username
    return redirect("/admin/mfa")
    

@app.route("/admin/mfa", methods=["GET", "POST"])
def admin_mfa():
    username = session.get("admin_pending")
    if not username:
        return redirect("/admin/login")

    with closing(get_db()) as db:
        cur = db.execute("""
            SELECT mfa_secret, mfa_confirmed
            FROM admin_users
            WHERE username = ?
        """, (username,))
        row = cur.fetchone()

    mfa_secret, confirmed = row

    if request.method == "GET":

    # MFA init: generate secret once
        if not mfa_secret:
            secret = base64.b32encode(os.urandom(20)).decode()
            with closing(get_db()) as db:
                db.execute("""
                    UPDATE admin_users
                    SET mfa_secret = ?, mfa_confirmed = 0
                    WHERE username = ?
                """, (secret, username))
                db.commit()

        return render_template(
            "admin_mfa.html",
            username=username,
            mfa_confirmed=bool(confirmed)
        )

    # POST → verify TOTP
    code = request.form.get("mfa_code")

    # First time → initialisatie
    if not mfa_secret:
        secret = base64.b32encode(os.urandom(20)).decode()
        totp = TOTP(secret)

        if not totp.verify(code):
            return render_template(
                "admin_mfa.html",
                error="Invalid code",
                mfa_confirmed=False
            )

        with closing(get_db()) as db:
            db.execute("""
                UPDATE admin_users
                SET mfa_secret = ?, mfa_confirmed = 1
                WHERE username = ?
            """, (secret, username))
            db.commit()

    else:
        totp = TOTP(mfa_secret)
        if not totp.verify(code):
            return render_template(
                "admin_mfa.html",
                error="Invalid code",
                mfa_confirmed=True
            )
         # MFA correct → confirm
        with closing(get_db()) as db:
            db.execute("""
                UPDATE admin_users
                SET mfa_confirmed = 1
                WHERE username = ?
            """, (username,))
            db.commit()

    # MFA OK → admin fully authenticated
    session.pop("admin_pending", None)
    session["admin_authenticated"] = True
    session["admin_user"] = username

    return redirect("/admin/dashboard")


@app.route("/admin/qr", methods=["GET"])
def admin_qr():
    username = session.get("admin_pending")
    if not username:
        return "", 403

    with closing(get_db()) as db:
        cur = db.execute("""
            SELECT mfa_secret
            FROM admin_users
            WHERE username = ?
        """, (username,))
        row = cur.fetchone()

    secret = row[0]

    if not secret:
        return "", 400

    totp = TOTP(secret)
    otp_url = totp.generate_otp_url("AdminPortal", username)

    img = qrcode.make(otp_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return Response(
        buf.getvalue(),
        mimetype="image/png",
        headers={"Cache-Control": "no-store"}
    )


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect("/admin/login")


# ------------------------------------------------------------
# Administrator panel - admin dashboard
# ------------------------------------------------------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin_authenticated"):
        return redirect("/admin/login")

    users = []

    with closing(get_db()) as db:
        cur = db.execute("""
            SELECT u.email,
                   CASE
                     WHEN m.email IS NULL THEN 'none'
                     WHEN m.mfa_confirmed = 0 THEN 'pending'
                     ELSE 'active'
                   END AS mfa_status
            FROM (
                SELECT DISTINCT email FROM issued_tokens
                UNION
                SELECT DISTINCT email FROM mfa_users
            ) u
            LEFT JOIN mfa_users m ON u.email = m.email
            ORDER BY u.email
        """)

        for row in cur.fetchall():
            users.append({
                "email": row[0],
                "mfa_status": row[1]
            })

    return render_template("admin_dashboard.html", users=users)


@app.route("/admin/user/challenge", methods=["POST"])
def admin_force_challenge():
    if not session.get("admin_authenticated"):
        return redirect("/admin/login")

    email = request.form.get("email")

    with closing(get_db()) as db:
        db.execute(
            "DELETE FROM issued_tokens WHERE email = ?",
            (email,)
        )
        db.commit()

    return redirect("/admin/dashboard")


@app.route("/admin/user/reset", methods=["POST"])
def admin_force_reset():
    if not session.get("admin_authenticated"):
        return redirect("/admin/login")

    email = request.form.get("email")

    with closing(get_db()) as db:
        db.execute("DELETE FROM issued_tokens WHERE email = ?", (email,))
        db.execute("DELETE FROM mfa_users WHERE email = ?", (email,))
        db.commit()

    return redirect("/admin/dashboard")

if __name__ == "__main__":
    cert_file = os.getenv("SSL_CERT_FILE", "cert.pem")
    key_file = os.getenv("SSL_KEY_FILE", "key.pem")
    # NOTE
    # Dovecot only accepts verified ssl certificates. Port 80, no ssl.
    # Thunberbird only accepts encrypted https. Port 443, ssl (may be self-signed).
    # NOTE
    port = int(os.getenv("PORT", "443"))

    app.run(
        debug=True,
        host="127.0.0.1",
        port=port,
        ssl_context=(cert_file, key_file),
    )
