from flask import Flask, render_template, request, redirect
import secrets
import base64
import os

from mfa import TOTP

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route("/", methods=["GET"])
def service_not_available():
    return "Service not available at this path.", 404


# temporary in-memory store
AUTH_CODES = {}
# Store the mfa_secret + mfa_digits + mfa_interval for users with MFA enabled
MFA_USERS = {}
# Store the Access Token, Refresh Token, Expiry, Scope for issued tokens along with associated email
ISSUED_TOKENS = {}


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
    AUTH_CODES[code] = {
        "email": email
    }

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
    print("Current AUTH_CODES store:", AUTH_CODES)

    code = request.form.get("code")

    if code in AUTH_CODES:
        print("Valid auth code received for email:", AUTH_CODES[code]["email"])

        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)

        # Store issued tokens
        ISSUED_TOKENS[access_token] = {
            "email": AUTH_CODES[code]["email"],
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,  # seconds (1 hour)
            "scope": "test_mail test_addressbook test_calendar"
        }

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
    # Log all incoming arguments for debugging
    form_payload = request.form.to_dict(flat=False)
    query_params = request.args.to_dict(flat=False)
    json_payload = request.get_json(silent=True)

    print("/token/verify request form:", form_payload)
    print("/token/verify request args:", query_params)
    print("/token/verify request json:", json_payload)

    access_token = request.form.get("token")

    if access_token in ISSUED_TOKENS:
        print("Valid access token received for email:",
              ISSUED_TOKENS[access_token]["email"])

        return {
            "active": True,
            "email": ISSUED_TOKENS[access_token]["email"],
            "scope": ISSUED_TOKENS[access_token]["scope"],
            "exp": ISSUED_TOKENS[access_token]["expires_in"],
            "token_type": ISSUED_TOKENS[access_token]["token_type"],
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

    # For demonstration purposes, we will assume that users with "mfa" in their email have MFA enabled
    if email and email in MFA_USERS:
        print(f"User {email} has MFA enabled.")
        return {
            "mfa_enabled": True
        }, 200
    else:
        print(f"User {email} does not have MFA enabled.")
        return {
            "mfa_enabled": False
        }, 200


@app.route("/mfa/register", methods=["POST"])
def mfa_register_endpoint():
    email = request.form.get("email")

    # For demonstration purposes, we will generate a dummy MFA secret and store it
    # Generate a random 20-byte secret and encode it in base32
    secret = os.urandom(20)
    secret_b32 = base64.b32encode(secret).decode('utf-8')

    # Store the MFA details for the user
    MFA_USERS[email] = {
        "mfa_secret": secret_b32,
        "mfa_digits": 6,
        "mfa_interval": 30
    }

    print(f"Registered MFA for user {email} with secret {secret_b32}")

    otp_url = TOTP(secret_b32).generate_otp_url("MFAPortal", email)

    return {
        "otp_url": otp_url
    }, 200


@app.route("/mfa/verify", methods=["POST"])
def mfa_verify_endpoint():
    email = request.form.get("email")
    mfa_code = request.form.get("mfa_code")

    secret_b32 = MFA_USERS.get(email, {}).get("mfa_secret", "")

    totp = TOTP(secret_b32)
    totp_code = totp.generate_totp()

    # For demonstration purposes, we will accept any MFA code "123456"
    if email in MFA_USERS and mfa_code == totp_code:
        print(f"MFA verification successful for user {email}")
        return {
            "mfa_verified": True
        }, 200
    else:
        print(f"MFA verification failed for user {email}")
        return {
            "mfa_verified": False
        }, 200


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
