from flask import Flask, request, render_template, redirect, url_for, session
import os

from database import DatabaseManager
from auth import AuthManager

app = Flask(__name__)
app.secret_key = os.urandom(24)
DbMgr = DatabaseManager()
AuthMgr = AuthManager()


# Redirect users to login page
@app.route("/", methods=["GET"])
def redirect_to_login():
    return redirect("/login")


@app.route("/login", methods=["GET"])
def login_get():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    email = request.form["email"]
    password = request.form["password"]

    session["pending_user"] = email
    return redirect(url_for("mfa_get"))


@app.route("/mfa", methods=["GET"])
def mfa_get():
    # als er geen pending_user is dan terug naar login
    if "pending_user" not in session:
        return redirect("/login")

    return render_template("mfa.html")


if __name__ == "__main__":
    app.run(debug=True)
