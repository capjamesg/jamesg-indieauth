import random
import string

import requests
from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

from config import (EMAIL_SENDER, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET,
                    GITHUB_OAUTH_REDIRECT, ME, POSTMARK_API_KEY)
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

    signed_in_with_correct_user = is_authenticated_as_allowed_user(me_url)

    if signed_in_with_correct_user is False:
        flash("You are not signed in with the correct user.")
        return redirect("/login")

    session["me"] = ME
    session["logged_in"] = True

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")


@callbacks.route("/auth/email")
def email_auth():
    email_verification_form = EmailVerificationCode()
    no_resend = request.args.get("no_resend")
    if request.method == "GET":
        me = session.get("me")
        email = "TODO"
        if no_resend != "true":
            random_code = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=6)
            )
            session["set_email_code"] = random_code
            message = f"""<p>Hello there,</p>

            <p>Artemis Auth wants you to sign in as {me}.</p>

            <p>To sign in, enter the following code:</p>

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
                "Subject": "Sign in with Artemis Auth",
                "HtmlBody": message,
                "MessageStream": "outbound",
            }

            try:
                response = requests.post(url, headers=headers, json=data)
                response.raise_for_status()
            except Exception as e:
                flash(
                    {
                        "message": "A passcode email was not sent due to an error. Please try again, or contact support at artemis@jamesg.blog.",
                        "type": "fail",
                    }
                )

        return render_template(
            "authentication_flow/email_auth.html",
            email_verification_form=email_verification_form,
            title="Email Authentication",
        )

    if email_verification_form.validate_on_submit():
        if email_verification_form.code.data == session.get("set_email_code"):
            session["me"] = session.get("me")
            session["logged_in"] = True

            if session.get("user_redirect"):
                redirect_uri = session.get("user_redirect")
                session.pop("user_redirect")
                return redirect(redirect_uri)

            return redirect("/")

        else:
            flash("The code you entered was incorrect. Please try again.")
            return redirect(url_for("callbacks.email_auth") + "?no_resend=true")
