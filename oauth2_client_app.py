from urllib.parse import urlencode
import flask
import hmac
import os
import requests
import secrets  # Python < 3.6: https://hg.python.org/cpython/file/3.6/Lib/secrets.py

app = flask.Flask(__name__)

# Usually, I put this envars in a `settings.py` module
APP_SECRETS_ENTROPY = int(os.environ.get("APP_SECRETS_ENTROPY", 88))
APP_CLIENT_ID = os.environ.get("APP_CLIENT_ID", "")
APP_CLIENT_SECRET = os.environ.get("APP_CLIENT_SECRET", "")
APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", secrets.token_hex(APP_SECRETS_ENTROPY))
SERVICE_URL = "http://localhost:6000"
SERVICE_STATE_SECRET_KEY = os.environ.get("APP_SECRET_KEY", secrets.token_hex(APP_SECRETS_ENTROPY))


@app.route("/")
def index():
    return flask.redirect(flask.url_for("service"))


@app.route("/service")
def service():
    access_token = flask.session.get("service_access_token", None)

    # If the app IS NOT AUTHORIZED, ask for authorization
    if access_token is None:
        return flask.redirect(flask.url_for("service_callback"))

    # If the app IS AUTHORIZED, use the token
    resource_request_uri = "{}/user".format(SERVICE_URL)
    resource_request_header = {"Authorization": "token {}".format(access_token)}
    try:
        protected_resource = requests.get(resource_request_uri,
                                          headers=resource_request_header)
        return dumps(protected_resource.json(), indent=4, sort_keys=True)
    except requests.exceptions.RequestException as e:
        # Correct way to try/except using Python requests module
        # http://stackoverflow.com/a/16511493/3281097
        exception_name = e.__class__.__name__
        return flask.redirect(flask.url_for("error", reason=exception_name, detail=e))


@app.route("/service/callback")
def service_callback():
    authorization_grant = flask.request.args.get("code", None)
    authorization_state = flask.request.args.get("state", "")

    # If we DO NOT RECEIVE AN AUTHORIZATION GRANT, request authorization
    if authorization_grant is None:
        authorization_request_state = secrets.token_urlsafe(APP_SECRETS_ENTROPY)
        flask.session["service_state"] = hmac.new(
            SERVICE_STATE_SECRET_KEY,
            msg=authorization_request_state.encode(),
            digestmod="sha256"
        ).hexdigest()
        authorization_request_uri = "{}/login/oauth/authorization".format(SERVICE_URL)
        authorization_request_params = {
            "client_id": APP_CLIENT_ID,
            "redirect_uri": url_for("service"),
            "response_type": "code",
            "scope": "email",
            "state": authorization_request_state
        }
        return flask.redirect(authorization_request_uri + "?" + urlencode(authorization_request_params))

    # If we RECEIVE AN AUTHORIZATION GRANT, check state and request an access token
    hashed_authorization_state = hmac.new(
        SERVICE_STATE_SECRET_KEY,
        msg=authorization_state.encode(),
        digestmod="sha256"
    ).hexdigest()
    if not hmac.compare_digest(flask.session["service_state"], hashed_authorization_state):
        flask.session.clear()
        return flask.redirect(flask.url_for("error", reason="CSRF verification failed.", detail="Request aborted."))
    access_token_request_uri = "{}/login/oauth/access_token".format(SERVICE_URL)
    access_token_request_header = {"Accept": "application/json"}
    access_token_request_params = {
        "client_id": APP_CLIENT_ID,
        "client_secret": APP_CLIENT_SECRET,
        "code": authorization_grant,
        "redirect_uri": url_for("service")
    }
    try:
        access_token_request = requests.post(access_token_request_uri,
                                             headers=access_token_request_header,
                                             data=access_token_request_params)
        flask.session["service_access_token"] = access_token_request.json().get("access_token", "")
        return flask.redirect(flask.url_for("service"))
    except requests.exceptions.RequestException as e:
        exception_name = e.__class__.__name__
        return flask.redirect(flask.url_for("error", reason=exception_name, detail=e))


@app.route("/error")
def error():
    reason = flask.request.args.get("reason", "WTF! (What the Flask)")
    detail = flask.request.args.get("detail", "You should not be here :(")
    html = list()
    html.append("<html>")
    html.append("<head><title>Error</title></head>")
    html.append("<body><h1>{}</h1>".format(reason))
    html.append("<h3>{}</h3></body>".format(detail))
    html.append("</html>")
    return "\n".join(html)

if __name__ == '__main__':
    app.debug = True
    app.secret_key = APP_SECRET_KEY  # This MUST be secret
    app.run()
