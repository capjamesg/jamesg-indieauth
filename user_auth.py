from flask import request, Blueprint, render_template, redirect, flash, session
from config import ME
import requests
import mf2py

user_auth = Blueprint('user_auth', __name__)

@user_auth.route("/login", methods=["GET", "POST"])
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

@user_auth.route("/rel")
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