from flask import Flask, render_template, request, redirect
import secrets
import base64
import os
import sqlite3
from contextlib import closing

from mfa import TOTP

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = "auth.db"
# Authorization codes are short-lived; store them in SQLite as well


def get_db():
    return sqlite3.connect(DB_PATH)


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
        db.commit()


init_db()


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
    # Log all incoming arguments for debugging
    form_payload = request.form.to_dict(flat=False)
    query_params = request.args.to_dict(flat=False)
    json_payload = request.get_json(silent=True)

    print("/token request form:", form_payload)
    print("/token request args:", query_params)
    print("/token request json:", json_payload)

    code = request.form.get("code")

    with closing(get_db()) as db:
        cur = db.execute(
            "SELECT email FROM auth_codes WHERE code = ?",
            (code,)
        )
        row = cur.fetchone()

    if row:
        email = row[0]
        print("Valid auth code received for email:", email)

        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)

        with closing(get_db()) as db:
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

        with closing(get_db()) as db:
            db.execute(
                "DELETE FROM auth_codes WHERE code = ?",
                (code,)
            )
            db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "test_mail test_addressbook test_calendar"
        }, 200
    else:
        return {
            "error": "invalid_grant",
            "error_description": "The provided authorization code is invalid or has expired."
        }, 400


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

    with closing(get_db()) as db:
        cur = db.execute(
            "SELECT 1 FROM mfa_users WHERE email = ?",
            (email,)
        )
        row = cur.fetchone()

    if row:
        print(f"User {email} has MFA enabled.")
        return {"mfa_enabled": True}, 200
    else:
        print(f"User {email} does not have MFA enabled.")
        return {"mfa_enabled": False}, 200


@app.route("/mfa/register", methods=["POST"])
def mfa_register_endpoint():
    email = request.form.get("email")

    secret = os.urandom(20)
    secret_b32 = base64.b32encode(secret).decode("utf-8")

    with closing(get_db()) as db:
        db.execute("""
            INSERT OR REPLACE INTO mfa_users
            (email, mfa_secret, mfa_digits, mfa_interval)
            VALUES (?, ?, ?, ?)
        """, (email, secret_b32, 6, 30))
        db.commit()

    print(f"Registered MFA for user {email} with secret {secret_b32}")

    otp_url = TOTP(secret_b32).generate_otp_url("MFAPortal", email)

    return {"otp_url": otp_url}, 200


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
        print(f"MFA verification successful for user {email}")
        return {"mfa_verified": True}, 200
    else:
        print(f"MFA verification failed for user {email}")
        return {"mfa_verified": False}, 200


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
