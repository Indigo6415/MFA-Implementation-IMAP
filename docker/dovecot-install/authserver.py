from flask import Flask, request, abort

app = Flask(__name__)


@app.route("/mfa", methods=["GET"])
def mfa_auth():
    # Get username and password from query parameters
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # Check password
    if password == "admin":
        return "", 200
    else:
        # Unauthorized
        abort(401)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
