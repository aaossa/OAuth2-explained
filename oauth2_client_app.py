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
    request_uri = "http://localhost:6000/user"
    response = requests.get(request_uri, headers=headers)
    return dumps(response.json(), indent=4, sort_keys=True)


@app.route("/service/callback")
def service_callback():
    # If we do NOT have a code, redirect user
    if "code" not in request.args:
        session["state"] = secrets.token_url()
        authorization_url = "http://localhost:6000/login/oauth/authorization?"
        authorization_params = urlencode({
            "client_id": APP_CLIENT_ID,
            "redirect_uri": url_for("service"),
            "response_type": "code",
            "scope": "giveit2me",
            "state": session["state"]
        })
        return redirect(authorization_url + authorization_params)

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
    exchange_request = requests.post(exchange_url, data=exchange_params)
    session["credentials"] = exchange_request.text
    return redirect(url_for("service"))


@app.route("/error")
def error(reason=None):
    if reason is None:
        abort(404)
    html = list()
    html.append("<head><title>Error</title></head>")
    html.append("<body><h1>{}</h1></body>".format(reason))
    return "\n".join(html)

if __name__ == '__main__':
    from uuid import uuid4
    app.secret_key = str(uuid4())
    app.debug = True
    app.run()
