from flask import Flask, request, render_template, redirect, url_for, session, abort
import os
import requests

from database import DatabaseManager
from auth import AuthManager
from totp_util import TOTP
import json
import io
from flask import send_file, flash

app = Flask(__name__)
app.secret_key = os.urandom(24)
DbMgr = DatabaseManager()
AuthMgr = AuthManager()


# Redirect users to login page
@app.route("/", methods=["GET"])
def redirect_to_login():
    return redirect("/form")


@app.route("/form", methods=["GET"])
def login_get():
    login_hint = request.args.get("login_hint")

    if not login_hint:
        abort(400, "login_hint missing")

    login_hint = login_hint.strip().lower()

    if "@" not in login_hint:
        abort(400, "login_hint is invalid")
    
    parts = login_hint.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        abort(400, "login_hint is invalid")

    email = login_hint
    domain = parts[1]

    return render_template("login.html",
                            email=email,
                            domain=domain)

def verify_with_domain(domain, email, password):
    url = f"https://{domain}/api/auth/verify"

    payload = {
        "email": email,
        "password": password
    }

    try:
        r = requests.post(url, json=payload, timeout=5)
    except requests.RequestException:
        return False

    if r.status_code != 200:
        return False

    try:
        data = r.json()
    except ValueError:
        return False

    return data.get("ok") is True
    
    # For test purposes disable code above and enable return true
    # return True


@app.route("/form", methods=["POST"])
def login_post():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template("login.html", email=email, error="Incorrect login")

    if "@" not in email:
        return render_template("login.html", email=email, error="Incorrect login")

    domain = email.split("@", 1)[1]

    ok = verify_with_domain(domain, email, password)
    if not ok:
        return render_template("login.html", email=email, error="Incorrect login")

    session["pending_user"] = email
    session["pending_domain"] = domain

    return redirect(url_for("mfa_get"))


@app.route("/mfa", methods=["GET"])
def mfa_get():
    # als er geen pending_user is dan terug naar login
    if "pending_user" not in session:
        return redirect("/form")

    user = session["pending_user"]

    # persistent storage for user secrets
    secrets_path = os.path.join(os.path.dirname(__file__), "mfa_secrets.json")
    if os.path.exists(secrets_path):
        with open(secrets_path, "r") as f:
            secrets = json.load(f)
    else:
        secrets = {}

    user_secret = secrets.get(user)

    if not user_secret:
        # generate a temporary secret if not present in session
        if "mfa_temp_secret" not in session:
            session["mfa_temp_secret"] = TOTP.generate_secret()

        qr_needed = True
        return render_template("mfa.html", qr_needed=qr_needed, issuer="MFA-Portal", account_name=user)

    # user already has a secret -> show input form only
    return render_template("mfa.html", qr_needed=False, issuer="MFA-Portal", account_name=user)


@app.route("/mfa/qr.png", methods=["GET"])
def mfa_qr():
    if "pending_user" not in session:
        return redirect("/form")

    user = session["pending_user"]
    # prefer temp secret during setup
    secret = session.get("mfa_temp_secret")
    # if user already has saved secret, use that instead
    secrets_path = os.path.join(os.path.dirname(__file__), "mfa_secrets.json")
    if os.path.exists(secrets_path):
        try:
            with open(secrets_path, "r") as f:
                secrets = json.load(f)
            secret = secrets.get(user, secret)
        except Exception:
            pass

    if not secret:
        return ("No secret available", 400)

    totp = TOTP(secret)
    png = totp.qr_png_bytes(issuer="MFA-Portal", account_name=user)
    return send_file(io.BytesIO(png), mimetype="image/png")


@app.route("/mfa", methods=["POST"])
def mfa_post():
    if "pending_user" not in session:
        return redirect("/form")

    user = session["pending_user"]
    token = request.form.get("totp", "").strip()
    if not token:
        return render_template("mfa.html", qr_needed=("mfa_temp_secret" in session), error="Enter a code", issuer="MFA-Portal", account_name=user)

    # load stored secrets
    secrets_path = os.path.join(os.path.dirname(__file__), "mfa_secrets.json")
    if os.path.exists(secrets_path):
        with open(secrets_path, "r") as f:
            try:
                secrets = json.load(f)
            except Exception:
                secrets = {}
    else:
        secrets = {}

    user_secret = secrets.get(user)

    if not user_secret:
        # try verifying against temp secret
        temp = session.get("mfa_temp_secret")
        if not temp:
            return render_template("mfa.html", qr_needed=True, error="No setup in progress", issuer="MFA-Portal", account_name=user)

        totp = TOTP(temp)
        if totp.verify(token):
            # persist secret
            secrets[user] = temp
            with open(secrets_path, "w") as f:
                json.dump(secrets, f)
            session.pop("mfa_temp_secret", None)
            session["mfa_authenticated"] = True
            return render_template("mfa.html", success="MFA enabled and verified.", qr_needed=False, issuer="MFA-Portal", account_name=user)
        else:
            return render_template("mfa.html", qr_needed=True, error="Invalid code", issuer="MFA-Portal", account_name=user)

    # user has stored secret -> verify
    totp = TOTP(user_secret)
    if totp.verify(token):
        session["mfa_authenticated"] = True
        return render_template("mfa.html", success="Code valid", qr_needed=False, issuer="MFA-Portal", account_name=user)

    return render_template("mfa.html", qr_needed=False, error="Invalid code", issuer="MFA-Portal", account_name=user)


if __name__ == "__main__":
    app.run(debug=True)
