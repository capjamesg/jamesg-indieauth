from flask import request, Blueprint, jsonify, render_template, redirect, flash, session
from .config import TWITTER_OAUTH_KEY, TWITTER_OAUTH_SECRET, ME, GITHUB_CLIENT_ID, GITHUB_OAUTH_REDIRECT, GITHUB_CLIENT_SECRET, \
    OKTA_DOMAIN, OKTA_USER_ID, OKTA_FACTOR_ID, OKTA_ACCESS_TOKEN
import string
import random
import requests
import tweepy

callbacks = Blueprint('callbacks', __name__)

@callbacks.route("/auth/twitter")
def twitter_auth():
    auth = tweepy.OAuthHandler(TWITTER_OAUTH_KEY, TWITTER_OAUTH_SECRET)
    auth_url = auth.get_authorization_url()
    session["request_token"] = auth.request_token
    session.pop("rel_me_check")
    return redirect(auth_url)

@callbacks.route("/auth/github")
def github_auth():
    state = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    session["github_state"] = state
    return redirect("https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}".format(GITHUB_CLIENT_ID, GITHUB_OAUTH_REDIRECT, state))

@callbacks.route("/auth/github/callback")
def github_callback():
    access_token = request.args.get("code")
    state = request.args.get("state")

    if state != session.get("github_state"):
        return redirect("/login")

    session.pop("github_state")

    headers = {
        "Accept": "application/json"
    }

    r = requests.post("https://github.com/login/oauth/access_token?client_id={}&client_secret={}&code={}&redirect_uri={}".format(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, access_token, GITHUB_OAUTH_REDIRECT), headers=headers)

    if not r.json().get("access_token"):
        flash("There was an error authenticating with GitHub.")
        return redirect("/login")

    user_request = requests.get("https://api.github.com/user", headers={"Authorization": "token {}".format(r.json()["access_token"])})

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
        return redirect(redirect_uri)

    return redirect("/")

@callbacks.route("/auth/twitter/callback")
def twitter_callback():
    auth = tweepy.OAuthHandler(TWITTER_OAUTH_KEY, TWITTER_OAUTH_SECRET)

    try:
        auth.request_token = {
            "oauth_token": request.args.get("oauth_token"),
            "oauth_token_secret": request.args.get("oauth_verifier")
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
        "Authorization": "SSWS {}".format(OKTA_ACCESS_TOKEN)
    }

    r = requests.post("{}/api/v1/users/{}/factors/{}/verify".format(OKTA_DOMAIN, OKTA_USER_ID, OKTA_FACTOR_ID), headers=headers)

    if r.status_code != 201:
        flash("There was an error authenticating with Okta.")
        return redirect("/login")

    session["transaction_id"] = r.json()["_links"]["poll"]["href"]

    return render_template("passwordless.html", title="Authenticate with a passwordless link")

@callbacks.route("/auth/passwordless/check")
def passwordless_check():
    if session.get("transaction_id") == None:
        return redirect("/login")

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "SSWS {}".format(OKTA_ACCESS_TOKEN)
    }

    r = requests.get(session.get("transaction_id"), headers=headers)

    if r.status_code != 200:
        flash("There was an error authenticating with Okta.")
        return render_template("passwordless.html", title="Authenticate with a passwordless link")

    if r.json()["factorResult"] != "SUCCESS":
        flash("There was an error authenticating with Okta.")
        return render_template("passwordless.html", title="Authenticate with a passwordless link")

    session["me"] = ME
    session["logged_in"] = True

    if session.get("user_redirect"):
        redirect_uri = session.get("user_redirect")
        session.pop("user_redirect")
        return redirect(redirect_uri)

    return redirect("/")