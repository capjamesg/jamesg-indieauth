import random
import string
from datetime import datetime, timedelta

import jwt
import requests
from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

import config
from cache import h_card_cache
from config import (EMAIL_SENDER, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET,
                    GITHUB_OAUTH_REDIRECT, POSTMARK_API_KEY)
from forms import EmailVerificationCode
from helpers import is_authenticated_as_allowed_user

callbacks = Blueprint("callbacks", __name__)


@callbacks.route("/auth/github")
def github_auth():
    state = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(32)
    )
    session["github_state"] = state
    return redirect(
        f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_OAUTH_REDIRECT}&state={state}"
    )


@callbacks.route("/auth/github/callback")
def github_callback():
    access_token = request.args.get("code")
    state = request.args.get("state")

    if state != session.get("github_state"):
        return redirect("/login")

    session.pop("github_state")

    r = requests.post(
        f"https://github.com/login/oauth/access_token?client_id={GITHUB_CLIENT_ID}&client_secret={GITHUB_CLIENT_SECRET}&code={access_token}&redirect_uri={GITHUB_OAUTH_REDIRECT}",
        headers={"Accept": "application/json"},
    )

    if not r.json().get("access_token"):
        flash("There was an error authenticating with GitHub.")
        return redirect("/login")

    user_request = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"token {r.json()['access_token']}"},
    )

    if user_request.status_code != 200:
        flash("There was an error authenticating with GitHub.")
        return redirect("/login")

    user = user_request.json()

    me = user.get("login")
    me_url = "https://github.com/" + me

    signed_in_with_correct_user = is_authenticated_as_allowed_user(
        session.get("rel_me_check"), me_url
    )

    if signed_in_with_correct_user is False:
        flash("You are not signed in with the correct user.")
        return redirect("/login")

    session["me"] = session.get("rel_me_check")
    session["logged_in"] = True
    session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")


@callbacks.route("/verify_email")
def verify_email():
    token = request.args.get("token")
    if not token:
        flash("There was an error verifying your email.")
        return redirect("/login")

    try:
        decoded_token = jwt.decode(token, "secret", algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        flash("The verification link has expired. Please try signing in again.")
        return redirect("/login")
    except jwt.InvalidTokenError:
        flash("The verification link is invalid. Please try signing in again.")
        return redirect("/login")

    if decoded_token.get("action") != "email_auth":
        flash("The verification link is invalid. Please try signing in again.")
        return redirect("/login")

    session["me"] = session.get("rel_me_check")
    session["logged_in"] = True
    session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")


@callbacks.route("/auth/email", methods=["GET", "POST"])
def email_auth():
    email_verification_form = EmailVerificationCode()
    no_resend = request.args.get("no_resend")
    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")
    if request.method == "GET":
        me = session.get("me")
        email = session.get("rel_me_email")

        jwt_payload = {
            "me": me,
            "email": email,
            "action": "email_auth",
            "auth_time": datetime.utcnow(),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=5),
            "random": "".join(
                random.choices(string.ascii_uppercase + string.digits, k=12)
            ),
        }

        jwt_token = jwt.encode(jwt_payload, config.SECRET_KEY, algorithm="HS256")

        if no_resend != "true":
            random_code = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=6)
            )
            session["set_email_code"] = random_code
            session["set_email_code_time"] = datetime.utcnow().isoformat()

            message = f"""<p>Hello there,</p>

            <p>Alto wants you to sign in as {me}.</p>

            <p>You can click the link below to sign in, or enter the code below on the Alto sign-in page.</p>

            <p><a href="{request.url_root}callbacks/verify_email?token={jwt_token}">{request.url_root}callbacks/verify_email?token={jwt_token}</a></p>

            <p>Your sign in code is:</p>

            <p><b>{random_code}</b></p>
            """
            url = "https://api.postmarkapp.com/email"

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Postmark-Server-Token": POSTMARK_API_KEY,
            }

            data = {
                "From": EMAIL_SENDER,
                "To": email,
                "Subject": "Sign in with Alto",
                "HtmlBody": message,
                "MessageStream": "outbound",
            }

            try:
                response = requests.post(url, headers=headers, json=data)
                response.raise_for_status()
            except Exception as e:
                flash(
                    {
                        "message": "A passcode email was not sent due to an error. Please try again, or contact support at "
                        + EMAIL_SENDER
                        + ".",
                        "type": "fail",
                    }
                )

        return render_template(
            "authentication_flow/email_auth.html",
            email_verification_form=email_verification_form,
            title="Email Authentication",
            representative_h_card=h_card_cache.get(session.get("rel_me_check")),
        )

    if email_verification_form.validate_on_submit():
        if email_verification_form.code.data == session.get("set_email_code"):
            # if time is more than 5 minutes from set_email_code_time, reject
            code_time = datetime.fromisoformat(session.get("set_email_code_time"))
            if datetime.utcnow() > code_time + timedelta(minutes=5):
                flash("The code you entered has expired. Please try again.")
                return redirect(url_for("callbacks.email_auth") + "?no_resend=true")
            
            session["me"] = session.get("rel_me_check")
            session["logged_in"] = True
            session["h_card"] = h_card_cache.get(session.get("rel_me_check"))

            if session.get("user_redirect"):
                redirect_uri = session.get("user_redirect")
                session.pop("user_redirect")
                return redirect(redirect_uri)

            return redirect("/")

        else:
            flash("The code you entered was incorrect. Please try again.")
            return redirect(url_for("callbacks.email_auth") + "?no_resend=true")

