import base64
import datetime
import hashlib
import json
import random
import sqlite3
import string
import time
from urllib.parse import urlparse as parse_url

import jwt
import requests
from bs4 import BeautifulSoup
from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, session)

from config import (API_KEY, AUTH_SERVER_URL, SECRET_KEY, WEBHOOK_ACCESS_TOKEN,
                    WEBHOOK_SERVER, WEBHOOK_URL)
from helpers import verify_code
from scopes import SCOPE_DEFINITIONS

app = Blueprint("app", __name__)


def get_h_app_item(web_page, client_id, redirect_uri_scheme, redirect_uri_domain):
    h_x_app = BeautifulSoup(web_page, "lxml")
    h_app_item = h_x_app.select(".h-app")

    if not h_app_item:
        h_app_item = h_x_app.select(".h-x-app")

    if h_app_item:
        h_app_item = h_app_item[0]
        logo = h_app_item.select(".u-logo")
        name = h_app_item.select(".p-name")
        url = h_app_item.select(".u-url")
        summary = h_app_item.select(".p-summary")

        h_app_item = {}

        if name and name[0].text.strip() != "":
            h_app_item["name"] = name[0].text
        else:
            h_app_item["name"] = client_id

        if logo and len(logo) > 0 and logo[0].get("src"):
            logo_to_validate = logo[0].get("src")
            if logo[0].get("src").startswith("/"):
                logo_to_validate = (
                    redirect_uri_scheme
                    + redirect_uri_domain.strip("/")
                    + logo[0].get("src")
                )
            elif logo[0].get("src").startswith("//"):
                logo_to_validate = redirect_uri_scheme + logo[0].get("src")
            elif logo[0].get("src").startswith("http://") or logo[0].get(
                "src"
            ).startswith("https://"):
                logo_to_validate = logo[0].get("src")
            else:
                logo_to_validate = (
                    redirect_uri_scheme
                    + redirect_uri_domain.strip("/")
                    + "/"
                    + logo[0].get("src")
                )

            h_app_item["logo"] = logo_to_validate

        if url and url[0].get("href").strip() != "":
            h_app_item["url"] = url[0].get("href")
        else:
            h_app_item["url"] = client_id

        if summary and summary[0].text.strip() != "":
            h_app_item["summary"] = summary[0].text

    return h_app_item


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("me", None)

    return redirect("/")


@app.route("/auth", methods=["GET", "POST"])
def authorization_endpoint():
    if request.method == "GET":
        me = request.args.get("me")

        if (
            request.args.get("me")
            and session.get("me")
            and request.args.get("me").strip("/") != session.get("me").strip("/")
        ):
            session.pop("logged_in", None)
            session.pop("me", None)
            flash(
                f"""
                {request.args.get('client_id')} is requesting you to sign in as {request.args.get('me')}.
                Please sign in as {request.args.get('me')}.
            """
            )
            return redirect(f"/login?r={request.url}")

        if session.get("logged_in") != True:
            return redirect(f"/login?r={request.url}")

        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        response_type = request.args.get("response_type")
        state = request.args.get("state")
        code_challenge = request.args.get("code_challenge")
        code_challenge_method = request.args.get("code_challenge_method")
        scope = request.args.get("scope")

        if not client_id or not redirect_uri or not response_type or not state:
            return jsonify({"error": "invalid_request."})

        if response_type != "code" and response_type != "id":
            return jsonify({"error": "invalid_request"})

        try:
            client_id_app = requests.get(client_id)
        except:
            return jsonify({"error": "invalid_request"})

        h_app_item = None

        redirect_uri_domain = parse_url(redirect_uri).netloc
        client_id_domain = parse_url(client_id).netloc

        redirect_uri_scheme = parse_url(redirect_uri).scheme
        client_id_scheme = parse_url(client_id).scheme

        if (
            redirect_uri_domain != client_id_domain
            or redirect_uri_scheme != client_id_scheme
        ):
            fetch_client = requests.get(client_id)

            link_headers = fetch_client.headers.get("link")

            confirmed_redirect_uri = False

            if link_headers:
                for link in link_headers.split(","):
                    if 'rel="redirect_uri"' in link:
                        url = link.split(";")[0].strip("<>")

                        if url.startswith("/"):
                            url = (
                                redirect_uri_scheme
                                + redirect_uri_domain.strip("/")
                                + url
                            )

                        if url == redirect_uri:
                            confirmed_redirect_uri = True

            link_tags = BeautifulSoup(fetch_client.text, "lxml").find_all("link")

            for link in link_tags:
                if link.get("rel") == "redirect_uri":
                    URL = link.get("href")

                    if url.startswith("/"):
                        url = redirect_uri_scheme + redirect_uri_domain.strip("/") + url

                    if url == redirect_uri:
                        confirmed_redirect_uri = True

            if not confirmed_redirect_uri:
                return jsonify({"error": "invalid_request"})

        if client_id_app.status_code == 200:
            h_app_item = get_h_app_item(
                client_id_app.text, client_id, redirect_uri_scheme, redirect_uri_domain
            )

        return render_template(
            "authentication_flow/confirm_auth.html",
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
            title=f"Authenticate to {client_id.replace('https://', '').replace('http://', '').strip()}",
        )

    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    code_challenge = request.form.get("code_challenge")
    code_challenge_method = request.form.get("code_challenge_method")

    if grant_type != "authorization_code":
        return jsonify({"error": "invalid_request"})

    if not code or not client_id or not redirect_uri:
        return jsonify({"error": "invalid_request"})

    if code_challenge and code_challenge_method:
        if code_challenge_method != "S256":
            return jsonify({"error": "invalid_request"})

        if len(code_challenge) < 43:
            return jsonify({"error": "invalid_request"})

        if len(code_challenge) > 128:
            return jsonify({"error": "invalid_request"})

    try:
        decoded_code = jwt.decode(code, SECRET_KEY, algorithms=["HS256"])
    except:
        return jsonify({"error": "invalid_grant"})

    message = verify_code(client_id, redirect_uri, decoded_code)

    if message != None:
        return jsonify({"error": message})

    return jsonify({"me": decoded_code["me"].strip("/") + "/"})


@app.route("/issued")
def view_issued_tokens():
    is_feed_view = request.args.get("feed")
    authorization_token = request.args.get("authorization")
    token = request.args.get("token")

    if token:
        connection = sqlite3.connect("tokens.db")

        with connection:
            cursor = connection.cursor()

            issued_tokens = cursor.execute(
                "SELECT * FROM issued_tokens WHERE token = ?", (token,)
            ).fetchone()

            if len(issued_tokens) == 0:
                abort(404)

        token_app = json.loads(issued_tokens[0][5])

        return render_template(
            "admin/single_token.html",
            title="About an Issued Token",
            token_app=token_app,
            token=issued_tokens[0],
            SCOPE_DEFINITIONS=SCOPE_DEFINITIONS,
        )

    if not session.get("logged_in") and authorization_token != API_KEY:
        return redirect("/login")

    connection = sqlite3.connect("tokens.db")

    with connection:
        cursor = connection.cursor()

        issued_tokens = cursor.execute("SELECT * FROM issued_tokens").fetchall()

    if is_feed_view == "true":
        template = "admin/issued_feed.html"
    else:
        template = "admin/issued.html"

    return render_template(
        template,
        title="Issued Tokens",
        issued_tokens=issued_tokens,
        SCOPE_DEFINITIONS=SCOPE_DEFINITIONS,
    )


@app.route("/generate", methods=["POST"])
def generate_key():
    if session.get("logged_in") != True:
        return redirect(f"/login?r={request.url}")

    me = request.form.get("me")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    response_type = request.form.get("response_type")
    state = request.form.get("state")
    code_challenge = request.form.get("code_challenge")
    code_challenge_method = request.form.get("code_challenge_method")
    scope = request.form.get("scope").lower()
    is_manually_issued = request.form.get("is_manually_issued")

    if (
        not client_id
        or not redirect_uri
        or not response_type
        or (not state and state != "")
    ):
        return jsonify({"error": "invalid_request"})

    if response_type != "code" and response_type != "id":
        return jsonify({"error": "invalid_request"})

    final_scope = ""

    for item in scope.split(" "):
        if request.form.get(f"scope_{item}"):
            final_scope += f"{item} "

    client_id_app = requests.get(client_id)

    redirect_uri_scheme = parse_url(redirect_uri).scheme
    redirect_uri_domain = parse_url(redirect_uri).netloc

    h_app_item = get_h_app_item(
        client_id_app.text, client_id, redirect_uri_scheme, redirect_uri_domain
    )

    random_string = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(10)
    )

    encoded_code = jwt.encode(
        {
            "me": me,
            "random_string": random_string,
            "expires": int(time.time()) + 3600,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": final_scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        },
        SECRET_KEY,
        algorithm="HS256",
    )

    connection = sqlite3.connect("tokens.db")

    with connection:
        cursor = connection.cursor()

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        already_issued_to_client = cursor.execute(
            "SELECT * FROM issued_tokens WHERE client_id = ?", (client_id,)
        ).fetchall()

        # delete tokens that have already been issued to the client
        # ensures that more than one token cannot be active per client
        if len(already_issued_to_client) > 0:
            cursor.execute(
                "DELETE FROM issued_tokens WHERE client_id = ?", (client_id,)
            )

        cursor.execute(
            "INSERT INTO issued_tokens VALUES (?, ?, ?, ?, ?, ?)",
            (
                encoded_code,
                me,
                now,
                client_id,
                int(time.time()) + 3600,
                json.dumps(h_app_item),
            ),
        )

    if is_manually_issued and is_manually_issued == "true":
        flash(
            f"<p>Your token was successfully issued.</p><p>Your new token is: {encoded_code}"
        )
        return redirect("/issued")

    if WEBHOOK_SERVER == True:
        data = {"message": f"{me} has issued an access token to {client_id}"}

        headers = {"Authorization": f"Bearer {WEBHOOK_ACCESS_TOKEN}"}

        requests.post(WEBHOOK_URL, data=data, headers=headers)

    return redirect(redirect_uri.strip("/") + f"?code={encoded_code}&state={state}")


@app.route("/revoke")
def revoke_from_user_interface():
    token_to_revoke = request.args.get("token")

    if not token_to_revoke:
        return jsonify({"error": "invalid_request"})

    connection = sqlite3.connect("tokens.db")

    with connection:
        cursor = connection.cursor()
        if token_to_revoke == "all":
            cursor.execute("DELETE FROM issued_tokens")
        else:
            cursor.execute(
                "DELETE FROM issued_tokens WHERE token = ?", (token_to_revoke,)
            )

    r = requests.post(
        AUTH_SERVER_URL.strip("/") + "/token",
        data={"token": token_to_revoke, "action": "revoke"},
    )

    if r.status_code == 200:
        flash("Your token was revoked")
    else:
        flash("There was an error revoking your token")

    return redirect("/issued")


@app.route("/token", methods=["GET", "POST"])
def token_endpoint():
    if request.method == "GET":
        authorization = request.headers.get("authorization")

        if authorization == None:
            return jsonify({"error": "invalid_request"})

        connection = sqlite3.connect("tokens.db")

        with connection:
            cursor = connection.cursor()

            is_revoked = cursor.execute(
                "SELECT * FROM revoked_tokens WHERE token = ?", (authorization,)
            ).fetchone()

            if is_revoked:
                return jsonify({"error": "invalid_grant"})

        authorization = authorization.replace("Bearer ", "")

        try:
            decoded_authorization_code = jwt.decode(
                authorization, SECRET_KEY, algorithms=["HS256"]
            )
        except Exception as e:
            return jsonify({"error": "invalid_code"})

        if int(time.time()) > decoded_authorization_code["expires"]:
            return jsonify({"error": "invalid_grant"})

        me = decoded_authorization_code["me"]
        client_id = decoded_authorization_code["client_id"]
        scope = decoded_authorization_code["scope"]

        resource = decoded_authorization_code["resource"]

        if resource != "all":
            if request.path not in resource:
                return jsonify({"error": "invalid_request"})

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

                return jsonify(
                    {
                        "me": me.strip("/") + "/",
                        "client_id": client_id,
                        "scope": scope,
                        "profile": profile,
                    }
                )

        return jsonify(
            {"me": me.strip("/") + "/", "client_id": client_id, "scope": scope}
        )

    action = request.form.get("action")

    if action and action == "revoke":
        connection = sqlite3.connect("tokens.db")

        with connection:
            cursor = connection.cursor()

            cursor.execute(
                "INSERT INTO revoked_tokens VALUES (?)", (request.form.get("token"),)
            )

        return "", 200

    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    code_verifier = request.form.get("code_verifier")

    if not code or not client_id or not redirect_uri or not grant_type:
        return jsonify({"error": "invalid_request"})

    if grant_type != "authorization_code":
        return jsonify({"error": "invalid_request"})

    try:
        decoded_code = jwt.decode(code, SECRET_KEY, algorithms=["HS256"])
    except Exception as e:
        return jsonify({"error": "Invalid code."})

    if code_verifier != None and decoded_code["code_challenge_method"] == "S256":
        sha256_code = hashlib.sha256(code_verifier.encode("utf-8")).hexdigest()

        code_challenge = base64.b64encode(sha256_code.encode("utf-8")).decode("utf-8")

        if code_challenge != decoded_code["code_challenge"]:
            return jsonify({"error": "invalid_request"})

    message = verify_code(client_id, redirect_uri, decoded_code)

    if message != None:
        return jsonify({"error": message})

    scope = decoded_code["scope"]
    me = decoded_code["me"]

    if grant_type == "authorization_code":
        access = "all"
    else:
        db = sqlite3.connect("tokens.db")

        with db:
            cursor = db.cursor()

            ticket = cursor.execute(
                "SELECT * FROM tickets WHERE token = ?", (code,)
            ).fetchone()

            if not ticket:
                return jsonify({"error": "invalid_ticket"}), 400

            access = ticket[1]

    access_token = jwt.encode(
        {
            "me": me,
            "expires": int(time.time()) + 360000,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "resource": access,
        },
        SECRET_KEY,
        algorithm="HS256",
    )

    return jsonify(
        {"access_token": access_token, "token_type": "Bearer", "scope": scope, "me": me}
    )


@app.route("/.well-known/oauth-authorization-server")
def oauth_authorization_server():
    oauth_server = {
        "authorization_endpoint": "https://auth.jamesg.blog/auth",
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
        "issuer": "https://auth.jamesg.blog/auth",
        "response_modes_supported": ["query"],
        "response_types_supported": ["code"],
        "scopes_supported": [
            "create",
            "update",
            "delete",
            "undelete",
            "media",
            "profile",
            "email",
            "read",
            "follow",
            "mute",
            "block",
            "channels",
        ],
        "token_endpoint": "https://auth.jamesg.blog/token",
    }

    return jsonify(oauth_server)
