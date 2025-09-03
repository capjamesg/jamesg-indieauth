from flask_wtf import FlaskForm
from wtforms import HiddenField, URLField, SubmitField, StringField
from wtforms.validators import URL, DataRequired


class AskForDomain(FlaskForm):
    domain = URLField(
        "Your domain name",
        validators=[DataRequired(), URL(require_tld=True)],
        render_kw={"placeholder": "example.com"},
    )
    submit = SubmitField("Login")


class ConfirmAuth(FlaskForm):
    client_id = HiddenField("client_id", validators=[DataRequired()])
    me = HiddenField("me", validators=[DataRequired()])
    scope = HiddenField("scope", validators=[DataRequired()])
    state = HiddenField("state", validators=[DataRequired()])
    redirect_uri = HiddenField("redirect_uri", validators=[DataRequired()])
    response_type = HiddenField("response_type", validators=[DataRequired()])
    code_challenge = HiddenField("code_challenge", validators=[DataRequired()])
    code_challenge_method = HiddenField(
        "code_challenge_method", validators=[DataRequired()]
    )
    submit = SubmitField("Sign in")


class EmailVerificationCode(FlaskForm):
    code = StringField(
        "code",
        validators=[DataRequired()],
        render_kw={"placeholder": "Verification code"},
    )
    submit = SubmitField("Verify")
