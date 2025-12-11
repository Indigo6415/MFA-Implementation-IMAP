import os
import sqlite3
import secrets
import base64
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

app = Flask(__name__)
app.secret_key = "change_me_in_real_setup"  # in productie: environment variable

DB_PATH = os.path.join(os.path.dirname(__file__), "mfa.db")
APP_PASSWD_FILE = "/etc/dovecot/app-passwd"


# =========================
#   DATABASE HELPERS
# =========================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialiseer de users-tabel met mfa_initialized-veld."""
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            mfa_secret TEXT,
            app_password TEXT,
            mfa_initialized INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def get_user(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row


def set_app_password(username, app_password):
    """Sla app password op in SQLite én in /etc/dovecot/app-passwd."""
    print(f"[set_app_password] Updating app-password for {username}...")

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO users (username, mfa_secret, app_password, mfa_initialized)
        VALUES (?, '', ?, 1)
        ON CONFLICT(username) DO UPDATE SET
            app_password=excluded.app_password,
            mfa_initialized=1
    """, (username, app_password))
    conn.commit()
    conn.close()

    # /etc/dovecot/app-passwd bijwerken
    lines = []
    if os.path.exists(APP_PASSWD_FILE):
        with open(APP_PASSWD_FILE, "r") as f:
            lines = f.readlines()

    # oude entries voor deze user verwijderen
    lines = [l for l in lines if not l.startswith(f"{username}:")]

    # nieuwe regel toevoegen
    lines.append(f"{username}:{{PLAIN}}{app_password}\n")

    with open(APP_PASSWD_FILE, "w") as f:
        f.writelines(lines)

    print(f"[set_app_password] Written {username} to {APP_PASSWD_FILE}")


def get_or_create_secret(username):
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
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row["mfa_secret"] if row and row["mfa_secret"] else None


def mark_mfa_initialized(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET mfa_initialized = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


# =========================
#   QR-CODE HELPER
# =========================

def generate_qr_code(secret, username):
    """
    Maak een otpauth:// URL en zet die om naar een base64 PNG QR-code,
    geschikt voor Microsoft Authenticator / Google Authenticator.
    """
    issuer = "MFA-Portal"
    otp_uri = (
        f"otpauth://totp/{issuer}:{username}"
        f"?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )

    qr = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    return qr_base64


# =========================
#   ROUTES
# =========================

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Nooit None naar PAM sturen
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            # <<< NU via flash, zodat het via base.html nice wordt getoond
            flash("Vul zowel gebruikersnaam als wachtwoord in.", "error")
            return redirect(url_for("login"))

        p = pam.pam()
        if p.authenticate(username, password):
            session["username"] = username

            user = get_user(username)
            if user and user["mfa_initialized"] == 1 and user["mfa_secret"]:
                # MFA al geinitialiseerd → direct naar challenge (alleen TOTP invoer)
                return redirect(url_for("mfa_challenge"))
            else:
                # MFA nog NIET geinitialiseerd → QR + secret tonen
                secret = get_or_create_secret(username)
                qr = generate_qr_code(secret, username)
                return render_template(
                    "mfa.html",
                    mode="init",   # QR-modus
                    secret=secret,
                    qr=qr,
                    username=username,  # <<< handig voor in de UI
                )
        else:
            # <<< Professionelere foutmelding via flash
            flash("Ongeldige gebruikersnaam of wachtwoord.", "error")
            return redirect(url_for("login"))

    # GET
    return render_template("login.html")


@app.route("/mfa", methods=["GET", "POST"])
def mfa_challenge():
    username = session.get("username")
    if not username:
        flash("Je sessie is verlopen. Log opnieuw in.", "error")  # <<<
        return redirect(url_for("login"))

    user = get_user(username)
    secret = get_secret(username)
    if not secret:
        secret = get_or_create_secret(username)

    if request.method == "POST":
        code = request.form.get("code") or ""
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            # MFA OK → app-password genereren
            app_password = secrets.token_urlsafe(16)
            set_app_password(username, app_password)

            # Markeer MFA als geinitialiseerd (voor het geval dat nog niet zo was)
            if not user or user["mfa_initialized"] != 1:
                mark_mfa_initialized(username)

            # <<< Je kunt hier ook flashen dat het gelukt is, maar result.html is duidelijk genoeg
            return render_template(
                "result.html",
                app_password=app_password,
                username=username,  # <<< zodat je in de UI kunt tonen voor wie
            )
        else:
            # Foute code → flash + redirect terug naar de challenge
            flash("Ongeldige of verlopen code. Probeer het opnieuw.", "error")  # <<<
            return redirect(url_for("mfa_challenge"))

    # GET → alleen challenge scherm tonen (alleen TOTP invoer)
    return render_template("mfa.html", mode="challenge", username=username)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    else:
        # Voor het geval de tabel bestond zonder mfa_initialized,
        # proberen we een ALTER TABLE (stil falen als de kolom al bestaat).
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute("ALTER TABLE users ADD COLUMN mfa_initialized INTEGER DEFAULT 0")
            conn.commit()
        except sqlite3.OperationalError:
            # Kolom bestaat waarschijnlijk al
            pass
        conn.close()

    app.run(host="0.0.0.0", port=5000, debug=True)