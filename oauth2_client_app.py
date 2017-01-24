from flask import Flask, abort, redirect, request, session, url_for
from json import dumps, loads
from os import environ
from urllib.parse import urlencode
import requests
import secrets  # Python < 3.6: https://gist.github.com/aaossa/a4c83ad87cd61fbd4c06f37f5913d2e3

app = Flask(__name__)

# Usually, I put this envars in a `settings.py` module
APP_CLIENT_ID = environ.get("APP_CLIENT_ID", "")
APP_CLIENT_SECRET = environ.get("APP_CLIENT_SECRET", "")
APP_SECRET_KEY = environ.get("APP_SECRET_KEY", secrets.token_hex())
SERVICE_URL = "http://localhost:6000"


@app.route("/")
def index():
    return redirect(url_for("service"))


@app.route("/service")
def service():
    # If the user is not logged in, then ask for authorization
    if "credentials" not in session:
        return redirect(url_for("service_callback"))

    # Once the user is logged in, request a token to use
    credentials = loads(session["credentials"])
    headers = {"Authorization": "token {}".format(credentials["access_token"])}
    request_uri = "{}/user".format(SERVICE_URL)
    try:
        response = requests.get(request_uri, headers=headers)
        return dumps(response.json(), indent=4, sort_keys=True)
    except requests.exceptions.RequestException as e:
        # Correct way to try/except using Python requests module
        # http://stackoverflow.com/a/16511493/3281097
        return redirect(url_for("error", reason=e))


@app.route("/service/callback")
def service_callback():
    # If we do NOT have a code, redirect user
    if "code" not in request.args:
        session["state"] = secrets.token_hex()
        authorization_url = "{}/login/oauth/authorization".format(SERVICE_URL)
        authorization_params = urlencode({
            "client_id": APP_CLIENT_ID,
            "redirect_uri": url_for("service"),
            "response_type": "code",
            "scope": "email",
            "state": session["state"]
        })
        return redirect(authorization_url + "?" + authorization_params)

    # If we have a code, verify state, get a token and redirect
    authorization_code = request.args.get("code", "")
    authorization_state = request.args.get("state", "")
    if authorization_state != session["state"]:
        return redirect(url_for("error", reason="state"))
    exchange_url = "http://localhost:6000/login/oauth/access_token"
    exchange_params = {
        "client_id": APP_CLIENT_ID,
        "client_secret": APP_CLIENT_SECRET,
        "code": authorization_code,
        "redirect_uri": url_for("service")
    }
    try:
        exchange_request = requests.post(exchange_url, data=exchange_params)
        session["credentials"] = exchange_request.text
        return redirect(url_for("service"))
    except requests.exceptions.RequestException as e:
        return redirect(url_for("error", reason=e))


@app.route("/error")
def error():
    reason = request.args.get("reason")
    if reason is None:
        abort(404)
    html = list()
    html.append("<head><title>Error</title></head>")
    html.append("<body><h1>{}</h1></body>".format(reason))
    return "\n".join(html)

if __name__ == '__main__':
    app.debug = True
    app.secret_key = APP_SECRET_KEY  # This MUST be secret
    app.run()
