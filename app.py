import os, pathlib, requests
from flask import Flask, session, abort, redirect, request
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow

client_secret_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
GOOGLE_CLIENT_ID = "887569292704-m92pcj08v19ua0i28j7gf5b5qepie0e7.apps.googleusercontent.com"
flow = Flow.from_client_secrets_file(client_secrets_file=client_secret_file,
                                     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                     redirect_uri="http://127.0.0.1:5000/callback"
                                     )
app = Flask("BSI Login App")
app.secret_key = "testowy_tajny_klucz"

# bypassing https requirement
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

@app.route("/")
def index():
    return "<h1>Strona startowa</h1>" \
           "<br><a href='/login'><button>Logowanie</button></a>"


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/logout")
def logout():
    pass


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        return abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    return id_info
    # session["google_id"] = id_info.get("sub")
    # session["name"] = id_info.get("name")
    # return redirect("/protected_area")


def require_login(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # unauthorized
        else:
            return function

    return wrapper


@app.route("/protected")
@require_login
def protected():
    return "Protected site."


if __name__ == "__main__":
    app.run()
