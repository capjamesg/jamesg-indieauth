import random
import string

import requests
import tweepy
from flask import Blueprint, flash, redirect, render_template, request, session

from config import (
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_OAUTH_REDIRECT,
    ME,
    OKTA_ACCESS_TOKEN,
    OKTA_DOMAIN,
    OKTA_FACTOR_ID,
    OKTA_USER_ID,
)
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

    headers = {"Accept": "application/json"}

    r = requests.post(
        f"https://github.com/login/oauth/access_token?client_id={GITHUB_CLIENT_ID}&client_secret={GITHUB_CLIENT_SECRET}&code={access_token}&redirect_uri={GITHUB_OAUTH_REDIRECT}",
        headers=headers,
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


@callbacks.route("/auth/passwordless")
def passwordless_auth():
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {OKTA_ACCESS_TOKEN}",
    }

    r = requests.post(
        f"{OKTA_DOMAIN}/api/v1/users/{OKTA_USER_ID}/factors/{OKTA_FACTOR_ID}/verify",
        headers=headers,
    )

    if r.status_code != 201:
        flash("There was an error authenticating with Okta.")
        return redirect("/login")

    session["transaction_id"] = r.json()["_links"]["poll"]["href"]

    return render_template(
        "authentication_flow/passwordless.html",
        title="Authenticate with a passwordless link",
    )


@callbacks.route("/auth/passwordless/check")
def passwordless_check():
    if session.get("transaction_id") is None:
        return redirect("/login")

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {OKTA_ACCESS_TOKEN}",
    }

    r = requests.get(session.get("transaction_id"), headers=headers)

    if r.status_code != 200:
        flash("There was an error authenticating with Okta.")
        return render_template(
            "authentication_flow/passwordless.html",
            title="Authenticate with a passwordless link",
        )

    if r.json()["factorResult"] != "SUCCESS":
        flash("There was an error authenticating with Okta.")
        return render_template(
            "authentication_flow/passwordless.html",
            title="Authenticate with a passwordless link",
        )

    session["me"] = ME
    session["logged_in"] = True

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")
