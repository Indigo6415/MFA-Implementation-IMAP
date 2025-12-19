from flask import Flask, render_template, request, redirect
import secrets
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route("/", methods=["GET"])
def service_not_available():
    return "Service not available at this path.", 404


# temporary in-memory store
AUTH_CODES = {}


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
        return {
            "access_token": secrets.token_urlsafe(32),
            "refresh_token": secrets.token_urlsafe(32),
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "test_mail test_addressbook test_calendar"
        }, 200
    else:
        return {
            "error": "invalid_grant",
            "error_description": "The provided authorization code is invalid or has expired."
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


if __name__ == "__main__":
    cert_file = os.getenv("SSL_CERT_FILE", "cert.pem")
    key_file = os.getenv("SSL_KEY_FILE", "key.pem")
    port = int(os.getenv("PORT", "443"))

    app.run(
        debug=True,
        host="127.0.0.1",
        port=port,
        ssl_context=(cert_file, key_file),
    )
