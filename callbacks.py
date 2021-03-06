import random
import string

import requests
import tweepy
from flask import Blueprint, flash, redirect, render_template, request, session

from config import (GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET,
                    GITHUB_OAUTH_REDIRECT, ME, OKTA_ACCESS_TOKEN, OKTA_DOMAIN,
                    OKTA_FACTOR_ID, OKTA_USER_ID, TWITTER_OAUTH_KEY,
                    TWITTER_OAUTH_SECRET)
from helpers import get_rels

callbacks = Blueprint("callbacks", __name__)


@callbacks.route("/auth/twitter")
def twitter_auth():
    auth = tweepy.OAuthHandler(TWITTER_OAUTH_KEY, TWITTER_OAUTH_SECRET)
    auth_url = auth.get_authorization_url()
    session["request_token"] = auth.request_token
    session.pop("rel_me_check")
    return redirect(auth_url)


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

    signed_in_with_correct_user = get_rels(me_url)

    if signed_in_with_correct_user == False:
        flash("You are not signed in with the correct user.")
        return redirect("/login")

    session["me"] = ME
    session["logged_in"] = True

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")


@callbacks.route("/auth/twitter/callback")
def twitter_callback():
    auth = tweepy.OAuthHandler(TWITTER_OAUTH_KEY, TWITTER_OAUTH_SECRET)

    try:
        auth.request_token = {
            "oauth_token": request.args.get("oauth_token"),
            "oauth_token_secret": request.args.get("oauth_verifier"),
        }

        auth.get_access_token(verifier=request.args.get("oauth_verifier"))

        api = tweepy.API(auth)

        me = api.me().screen_name
        me_url = "https://twitter.com/" + me

        signed_in_with_correct_user = get_rels(me_url)

        if signed_in_with_correct_user == False:
            flash("You are not signed in with the correct user.")
            return redirect("/login")

        session["me"] = ME
        session["logged_in"] = True

        if session.get("user_redirect"):
            redirect_uri = session.get("user_redirect")
            session.pop("user_redirect")
            return redirect(redirect_uri)

        return redirect("/")
    except:
        flash("Twitter authorization failed. Please try again.")
        return redirect("/login")


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
        "passwordless.html", title="Authenticate with a passwordless link"
    )


@callbacks.route("/auth/passwordless/check")
def passwordless_check():
    if session.get("transaction_id") == None:
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
            "passwordless.html", title="Authenticate with a passwordless link"
        )

    if r.json()["factorResult"] != "SUCCESS":
        flash("There was an error authenticating with Okta.")
        return render_template(
            "passwordless.html", title="Authenticate with a passwordless link"
        )

    session["me"] = ME
    session["logged_in"] = True

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")
