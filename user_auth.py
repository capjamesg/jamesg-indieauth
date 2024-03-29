import indieweb_utils
from flask import Blueprint, flash, redirect, render_template, request, session

from config import ME

user_auth = Blueprint("user_auth", __name__)


@user_auth.route("/login", methods=["GET", "POST"])
def login():
    # only allow redirects to *.ME resources (i.e. wiki.jamesg.blog, if ME = jamesg.blog)
    if request.args.get("r") and request.args.get("r").split("/")[2].endswith(
        ME.strip("/").replace("https://", "").replace("http://", "")
    ):
        # this approach is used because args.get separates any ? in the r= query string
        session["user_redirect"] = request.args.get("r")

    if session.get("rel_me_check"):
        return redirect("/rel")

    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")

    if request.method == "POST":
        domain_name = request.form.get("domain")

        if domain_name.strip("/").replace("https://", "").replace(
            "http://", ""
        ) != ME.strip("/").replace("https://", "").replace("http://", ""):
            flash("Only approved domains can access this service.")
            return render_template(
                "authentication_flow/ask_for_domain.html",
                title="Login to capjamesg's IndieAuth Server",
            )

        session["rel_me_check"] = domain_name

        return redirect("/rel")
    return render_template(
        "authentication_flow/ask_for_domain.html",
        title="Login to capjamesg's IndieAuth Server",
    )


@user_auth.route("/rel")
def rel_login_stage():
    print('x')
    session["me"] = "jamesg.blog"
    if not session.get("rel_me_check"):
        return redirect("/login")

    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")

    rel_me_links = indieweb_utils.get_valid_relmeauth_links(session.get("rel_me_check"))

    return render_template(
        "authentication_flow/login.html",
        rel_me_links=rel_me_links,
        me=ME,
        title="Authenticate with a rel=me link",
    )
