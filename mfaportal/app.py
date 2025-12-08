from flask import Flask, request, render_template, redirect, url_for, session


app = Flask(__name__)

@app.get("/")
def authorize_get():
    return redirect("/login")

@app.get("/login")
def login_get():
    return render_template("login.html")
    
@app.post("/login")
def login_post():
    email = request.form["email"]
    password = request.form["password"]

    # Simpele validatie (in realiteit zou je hier een database check doen)
    # user = users.get(email)
    # if not user or not check_password_hash(user["password_hash"], password):
    #     return render_template("login.html", error="Incorrect information")

    session["pending_user"] = email
    return redirect(url_for("mfa_get"))


@app.get("/mfa")
def mfa_get():
    # als er geen pending_user is dan terug naar login
    if "pending_user" not in session:
        return redirect("/login")

    return render_template("mfa.html")
