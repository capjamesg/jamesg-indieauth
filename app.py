import datetime
import json
import sqlite3
import time
from urllib.parse import urlparse as parse_url

from dataclasses import asdict

import indieweb_utils
import jwt
import requests
from bs4 import BeautifulSoup
from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)

import config


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
    "draft": "Give permission to create draft posts",
    "post": "Give permission to post to your site",
}

app = Blueprint("app", __name__)


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

            confirmed_redirect_uri = False

            links = indieweb_utils.discover_endpoints(client_id, ["redirect_uri"])

            for url in links:
                if url.startswith("/"):
                    url = redirect_uri_scheme + redirect_uri_domain.strip("/") + url

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
            h_app_item = indieweb_utils.get_h_app_item(client_id_app.text, client_id)

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

    try:
        is_valid = indieweb_utils.validate_authorization_response(
            grant_type,
            code,
            client_id,
            redirect_uri,
            code_challenge,
            code_challenge_method,
        )
    except Exception:
        return jsonify({"error": "invalid_request"})

    if is_valid is False:
        return jsonify({"error": "invalid_request"})

    try:
        decoded_code = jwt.decode(code, SECRET_KEY, algorithms=["HS256"])
    except:
        return jsonify({"error": "invalid_grant"})

    try:
        indieweb_utils._verify_decoded_code(
            client_id,
            redirect_uri,
            decoded_code["client_id"],
            decoded_code["redirect_uri"],
            decoded_code["expires"],
        )
    except Exception as error_message:
        return jsonify({"error": error_message})

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

    if not session.get("logged_in") and authorization_token != config.API_KEY:
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
    code_challenge_method = request.form.get("code_challenge_method")
    scope = request.form.get("scope").lower()
    is_manually_issued = request.form.get("is_manually_issued")

    final_scope = ""

    for item in scope.split(" "):
        if request.form.get(f"scope_{item}"):
            final_scope += f"{item} "

    try:
        response = indieweb_utils.generate_auth_token(
            me,
            client_id,
            redirect_uri,
            response_type,
            state,
            code_challenge_method,
            final_scope,
            config.SECRET_KEY,
        )

        encoded_code = response.code
    except Exception:
        return jsonify({"error": "invalid_request"})

    try:
        client_id_app = requests.get(client_id, timeout=5)

        h_app_item = indieweb_utils.get_h_app_item(client_id_app.text, client_id)
    except Exception:
        h_app_item = {}

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
            "INSERT INTO issued_tokens VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                encoded_code,
                me,
                now,
                client_id,
                int(time.time()) + 3600,
                json.dumps(h_app_item),
                "" # scope
            ),
        )

    if is_manually_issued and is_manually_issued == "true":
        flash(
            f"<p>Your token was successfully issued.</p><p>Your new token is: {encoded_code}"
        )
        return redirect("/issued")

    if config.WEBHOOK_SERVER and config.WEBHOOK_SERVER == True:
        data = {"message": f"{me} has issued an access token to {client_id}"}

        headers = {"Authorization": f"Bearer {config.WEBHOOK_ACCESS_TOKEN}"}

        requests.post(config.WEBHOOK_URL, data=data, headers=headers)

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
        config.AUTH_SERVER_URL.strip("/") + "/token",
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

        if authorization is None:
            return jsonify({"error": "invalid_request"})
        
        grant_type = request.args.get("grant_type")
        me = request.args.get("me")

        if grant_type == "ticket":
            ticket = request.args.get("ticket")

            if not me:
                return jsonify({"error": "invalid_request"})

            if not ticket:
                return jsonify({"error": "invalid_request"})

            db = sqlite3.connect("tokens.db")

            with db:
                cursor = db.cursor()

                ticket = cursor.execute(
                    "SELECT * FROM tickets WHERE token = ?", (ticket,)
                ).fetchone()

                # ticket[0] is ticket
                # ticket[1] is scope

                if not ticket:
                    return jsonify({"error": "invalid_ticket"}), 400
                
                response = indieweb_utils.generate_auth_token(
                    me,
                    client_id,
                    redirect_uri,
                    "id",
                    "state",
                    "S256",
                    ticket[1],
                    config.SECRET_KEY,
                )

                encoded_code = response.code

                # save in db as issued token

                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                cursor.execute(
                    "INSERT INTO issued_tokens VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        encoded_code,
                        me,
                        now,
                        client_id,
                        int(time.time()) + 3600,
                        json.dumps({}),
                        resource,
                    ),
                )

                authorization = encoded_code

                return jsonify({"access_token": authorization, "token_type": "Bearer", "scope": ticket[1], "me": me})

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
                authorization, config.SECRET_KEY, algorithms=["HS256"]
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
            parsed_profile = indieweb_utils.get_profile(me)

            if parsed_profile:
                return jsonify(
                    {
                        "me": me.strip("/") + "/",
                        "client_id": client_id,
                        "scope": scope,
                        "profile": asdict(parsed_profile),
                    }
                )
            
        response = {"me": me.strip("/") + "/", "client_id": client_id, "scope": scope}

        db = sqlite3.connect("tokens.db")

        with db:
            cursor = db.cursor()

            issued_tokens = cursor.execute(
                "SELECT * FROM issued_tokens WHERE token = ?", (authorization,)
            ).fetchone()

            if not issued_tokens:
                return jsonify({"error": "invalid_grant"})

            response["resource"] = issued_tokens[6]

        return jsonify(response)

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
    try:
        redeem_code = indieweb_utils.redeem_code(
            grant_type,
            code,
            client_id,
            redirect_uri,
            code_verifier,
            config.SECRET_KEY,
            resource=access,
        )

        access_token = redeem_code.access_token
        scope = redeem_code.scope
        me = redeem_code.me
    except Exception:
        return jsonify({"error": "invalid_request"})

    return jsonify(
        {"access_token": access_token, "token_type": "Bearer", "scope": scope, "me": me}
    )

@app.route("/ticket-issuance")
def issue_ticket():
    if request.method == "POST":
        db = sqlite3.connect("tokens.db")

        with db:
            cursor = db.cursor()

            issuance_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # resource is the scope
            cursor.execute(
                "INSERT INTO tickets VALUES (?, ?, ?, ?)",
                (request.form.get("ticket"), request.form.get("resource"), issuance_time, request.form.get("subject")),
            )

            endpoints = indieweb_utils.discover_endpoints(
                request.form.get("target"), ["ticket_endpoint"]
            )

            ticket_endpoint = endpoints.get("ticket_endpoint")

            # make http request to send ticket
            try:
                requests.post(
                    ticket_endpoint,
                    data={"ticket": request.form.get("ticket"), "resource": request.form.get("resource"), "subject": request.form.get("subject")},
                )
            except:
                return jsonify({"error": "invalid_request"})
            
        # alert get_flashed_messages message
        flash("Your ticket was successfully issued.")
            
        return render_template("ticket_issuance.html", title="Issue a Ticket")
    
    return render_template("ticket_issuance.html", title="Issue a Ticket")

@app.route("/.well-known/oauth-authorization-server")
def oauth_authorization_server():
    oauth_server = {
        "authorization_endpoint": "https://auth.jamesg.blog/auth",
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
        "issuer": "https://auth.jamesg.blog/auth",
        "response_modes_supported": ["query"],
        "response_types_supported": ["code"],
        "scopes_supported": SCOPE_DEFINITIONS,
        "token_endpoint": "https://auth.jamesg.blog/token",
    }

    return jsonify(oauth_server)
