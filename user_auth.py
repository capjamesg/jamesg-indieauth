import indieweb_utils
from flask import Blueprint, flash, redirect, render_template, request, session

from config import ME
from forms import AskForDomain

user_auth = Blueprint("user_auth", __name__)


@user_auth.route("/login", methods=["GET", "POST"])
def login():
    ask_for_domain_form = AskForDomain()

    if request.args.get("r"):
        session["user_redirect"] = request.args.get("r")

    if session.get("rel_me_check"):
        return redirect("/rel")

    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")

    if request.method == "POST":
        if ask_for_domain_form.validate_on_submit():
            session["rel_me_check"] = ask_for_domain_form.domain.data
            return redirect("/rel")

    return render_template(
        "authentication_flow/ask_for_domain.html",
        title="Login to the Artemis Auth Server",
        ask_for_domain_form=ask_for_domain_form,
    )


@user_auth.route("/rel")
def rel_login_stage():
    if not session.get("rel_me_check"):
        return redirect("/login")

    if session.get("me"):
        if session.get("user_redirect"):
            return redirect(session.get("user_redirect"))

        return redirect("/")

    rel_me_links = indieweb_utils.get_valid_relmeauth_links(
        session.get("rel_me_check"), require_rel_me_link_back=False
    )

    return render_template(
        "authentication_flow/login.html",
        rel_me_links=rel_me_links,
        me=ME,
        title="Authenticate with a rel=me link",
    )
