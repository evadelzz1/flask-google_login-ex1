import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request, render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from dotenv import load_dotenv
import sqlite3

load_dotenv()

app = Flask("flask-login-app")
app.secret_key = os.environ.get("APP_SECRET")  # 필수: 앱의 비밀 키 설정

# HTTPS만을 지원하는 기능을 HTTP에서 테스트할 때 필요한 설정
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = os.environ.get("CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

# SQLITE CONFIG
conn = sqlite3.connect('users.sqlite3', check_same_thread=False)
cursor = conn.cursor()

def get_google_oauth_flow(redirect_uri):
    return Flow.from_client_secrets_file(
        client_secrets_file=client_secrets_file,
        scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri=redirect_uri
    )

@app.route("/")
def index():
    if "google_id" in session:
        return render_template('index.html', logged_in=True, username=session['name'])
    else:
        return render_template('index.html', logged_in=False)

@app.route('/googlelogin')
def google_login():
    flow = get_google_oauth_flow("http://localhost:3000/callback")
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow = get_google_oauth_flow("http://localhost:3000/callback")
    return handle_callback(flow, "state")

@app.route('/googlelogin_callback')
def google_login_callback():
    flow = get_google_oauth_flow("http://localhost:3000/login/callback")
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/login/callback")
def login_callback():
    flow = get_google_oauth_flow("http://localhost:3000/login/callback")
    return handle_callback(flow, "state")

def handle_callback(flow, state_key):
    if "google_id" in session:
        return redirect("/")
    
    # 상태 값 검증
    if state_key not in session or session[state_key] != request.args.get('state'):
        abort(500)  # State does not match!

    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    # 사용자 정보 가져오기
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    # 사용자 정보를 데이터베이스에 저장 또는 업데이트
    manage_user(id_info)

    # 세션 설정
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")

    return redirect("/")

def manage_user(id_info):
    # 사용자 정보 관리 로직 (생략)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)