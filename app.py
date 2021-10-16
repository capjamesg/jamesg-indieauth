from flask import request, Blueprint, jsonify, render_template, redirect, flash, session, current_app
from config import ME
import jwt
import string
import random
import mf2py
import requests
from bs4 import BeautifulSoup
import time
import sqlite3

app = Blueprint('app', __name__)

SCOPE_DEFINITIONS = {
    "create": "Give permission to create posts to your site",
    "update": " Give permission to update posts to your site",
    "delete": "Give permission to delete posts to your site",
    "undelete": "Give permission to undelete posts",
    "media": "Give permission to upload assets to your media endpoint",
    "profile": "Share your email, photo, and name from your website homepage (if available)",
    "email": "Share your email address",
    "read": "Give read access to channels in your feed reader",
    "follow": "Give permission to follow feeds",
    "mute": "Give permission to mute and unmute feeds",
    "block": "Give permission to block and unblock feeds",
    "channels": "Give permission to manage channels",
}

def get_rels(me_url):
    home = requests.get(ME)

    home_parsed = mf2py.parse(home.text)

    if home_parsed.get("rels") and home_parsed["rels"].get("me"):
        home_me_links = home_parsed["rels"]["me"]
    else:
        home_me_links = []

    for link in home_me_links:
        if link == me_url:
            return True

    return False

@app.route("/")
def index():
    return jsonify({"message": "Welcome to capjamesg's IndieAuth endpoint."})

@app.route("/auth", methods=['GET', 'POST'])
def authorization_endpoint():
    if request.method == "GET":
        if session.get("logged_in") != True:
            return redirect("/login?r={}" .format(request.url))

        me = request.args.get("me")
        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        response_type = request.args.get("response_type")
        state = request.args.get("state")
        code_challenge = request.args.get("code_challenge")
        code_challenge_method = request.args.get("code_challenge_method")
        scope = request.args.get("scope")

        if not client_id or not redirect_uri or not response_type or not state or not code_challenge or not code_challenge_method:
            return jsonify({"error": "Missing required parameters."})

        if response_type != "code":
            return jsonify({"error": "Only response_type=code is supported."})

        client_id_app = requests.get(client_id)

        h_app_item = None

        if client_id_app.status_code == 200:
            h_x_app = BeautifulSoup(client_id_app.text, "html.parser")
            h_app_item = h_x_app.select(".h-app")

            if h_app_item:
                h_app_item = h_app_item[0]
                logo = h_app_item.select(".u-logo")
                name = h_app_item.select(".p-name")
                url = h_app_item.select(".u-url")

                h_app_item = {}

                if name and name[0].text.strip() != "":
                    h_app_item["name"] = name[0].text
                else:
                    h_app_item["name"] = client_id

                if logo:
                    h_app_item["logo"] = logo[0].get("src")
                
                if url and url[0].get("href").strip() != "":
                    h_app_item["url"] = url[0].get("href")
                else:
                    h_app_item["url"] = client_id

        return render_template("confirm_auth.html",
            scope=scope,
            me=me,
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            h_app_item=h_app_item,
            SCOPE_DEFINITIONS=SCOPE_DEFINITIONS,
            title="Authenticate to {}".format(client_id.replace("https://", "").replace("http://", "").strip()))

    elif request.method == "POST":
        grant_type = request.form.get("grant_type")
        code = request.form.get("code")
        client_id = request.form.get("client_id")
        redirect_uri = request.form.get("redirect_uri")
        code_verifier = request.form.get("code_verifier")

        if grant_type != "authorization_code":
            return jsonify({"error": "Only grant_type=authorization_code is supported."})

        if not code or not client_id or not redirect_uri or not code_verifier:
            return jsonify({"error": "Missing required parameters."})

        try:
            decoded_code = jwt.decode(code, app.config["SECRET_KEY"], algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid code."})

        if int(time.time()) > decoded_code["expires"]:
            return jsonify({"error": "Code has expired."})

        if redirect_uri != decoded_code["redirect_uri"]:
            return jsonify({"error": "Invalid redirect_uri."})

        if client_id != decoded_code["client_id"]:
            return jsonify({"error": "Invalid client_id."})

        return jsonify({"me": decoded_code["me"]})
    else:
        return jsonify({"error": "Invalid request method."})   

@app.route("/generate", methods=["POST"])
def generate_key():
    if session.get("logged_in") != True:
        return redirect("/login?r={}" .format(request.url))

    me = request.form.get("me")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    response_type = request.form.get("response_type")
    state = request.form.get("state")
    code_challenge = request.form.get("code_challenge")
    code_challenge_method = request.form.get("code_challenge_method")
    scope = request.form.get("scope")

    if not client_id or not redirect_uri or not response_type or not state or not code_challenge or not code_challenge_method:
        return jsonify({"error": "Missing required parameters."})

    if response_type != "code":
        return jsonify({"error": "Only response_type=code is supported."})

    final_scope = ""

    for item in scope.split(" "):
        if request.form.get("scope_{}".format(item)):
            final_scope += "{} ".format(item)

    random_string = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

    encoded_code = jwt.encode(
        {"me": me, "random_string": random_string, "expires": int(time.time()) + 3600, "client_id": client_id, "redirect_uri": redirect_uri, "scope": final_scope},
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

    return redirect(redirect_uri.strip("/") + "?code={}&state={}".format(encoded_code, state))

@app.route("/token", methods=["GET", "POST"])
def token_endpoint():
    if request.method == "GET":
        authorization = request.headers.get("Authorization")

        if not authorization:
            return jsonify({"error": "Missing required parameters."})

        authorization = authorization.replace("Bearer ", "")

        try:
            decoded_authorization_code = jwt.decode(authorization, app.config["SECRET_KEY"], algorithms=["HS256"])

        except:
            return jsonify({"error": "invalid_code"})

        if int(time.time()) > decoded_authorization_code["expires"]:
            return jsonify({"error": "invalid_grant"})

        me = decoded_authorization_code["me"]
        client_id = decoded_authorization_code["client_id"]
        scope = decoded_authorization_code["scope"]

        if "profile" in scope:
            me_profile = requests.get(me)

            if me_profile:
                profile_item = BeautifulSoup(me_profile.text, "html.parser")
                h_card = profile_item.select(".h-card")

                if h_card:
                    h_card = h_card[0]
                    name = h_card.select(".p-name")
                    photo = h_card.select(".u-photo")
                    url = h_card.select(".u-url")
                    email = h_card.select(".u-email")

                    profile = {}

                    if name and name[0].text.strip() != "":
                        profile["name"] = name[0].text
                    else:
                        profile["name"] = me

                    if photo:
                        profile["photo"] = photo[0].get("src")
                    
                    if url and url[0].get("href").strip() != "":
                        profile["url"] = url[0].get("href")
                    else:
                        profile["url"] = me

                    if email:
                        profile["email"] = email[0].text.replace("mailto:", "")
                    else:
                        profile["email"] = None
                else:
                    profile = None

                return jsonify({"me": me, "client_id": client_id, "scope": scope, "profile": profile})

            return jsonify({"me": me, "client_id": client_id, "scope": scope})

    action = request.form.get("action")

    if action and action == "revoke":
        connection = sqlite3.connect("tokens.db")

        cursor = connection.cursor()

        cursor.execute("INSERT INTO revoked_tokens (token) VALUES (?)", (request.form.get("token"),))

    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    code_verifier = request.form.get("code_verifier")

    if not code or not client_id or not redirect_uri or not grant_type or not code_verifier:
        return jsonify({"error": "Missing required parameters."})

    if grant_type != "authorization_code":
        return jsonify({"error": "Only grant_type=authorization_code is supported."})

    try:
        decoded_code = jwt.decode(code, app.config["SECRET_KEY"], algorithms=["HS256"])
    except Exception as e:
        return jsonify({"error": "Invalid code."})

    if int(time.time()) > decoded_code["expires"]:
        return jsonify({"error": "Code has expired."})

    if redirect_uri != decoded_code["redirect_uri"]:
        return jsonify({"error": "Invalid redirect_uri."})

    if client_id != decoded_code["client_id"]:
        return jsonify({"error": "Invalid client_id."})

    scope = decoded_code["scope"]
    me = decoded_code["me"]

    access_token = jwt.encode(
        {"me": me, "expires": int(time.time()) + 360000, "client_id": client_id, "redirect_uri": redirect_uri, "scope": scope},
        current_app.config["SECRET_KEY"],
        algorithm="HS256"
    )
    
    return jsonify({"access_token": access_token, "token_type": "Bearer", "scope": scope, "me": me})

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("rel_me_check"):
        return redirect("/rel")

    if request.args.get("r"):
        session["user_redirect"] = request.args.get("r")

    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")

    if request.method == "POST":
        domain_name = request.form.get("domain")

        if domain_name.strip("/").replace("https://", "").replace("http://", "") != ME.strip("/").replace("https://", "").replace("http://", ""):
            flash("Only approved domains can access this service.")
            return render_template("ask_for_domain.html", title="Login to capjamesg's IndieAuth Server")

        session["rel_me_check"] = domain_name

        return redirect("/rel")
    return render_template("ask_for_domain.html", title="Login to capjamesg's IndieAuth Server")

@app.route("/rel")
def rel_login_stage():
    if not session.get("rel_me_check"):
        return redirect("/login")

    if session.get("me"):
        return redirect("/")

    rel_request = requests.get(session.get("rel_me_check"))

    parsed = mf2py.parse(rel_request.text)

    if parsed.get("rels") and parsed["rels"].get("me"):
        rel_me_links = parsed["rels"]["me"]
    else:
        rel_me_links = []

    return render_template("login.html", rel_me_links=rel_me_links, me=ME, title="Authenticate with a rel=me link")