from flask import Flask, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .config import SECRET_KEY
import os

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    # read config.py file
    app.config.from_pyfile(os.path.join(".", "config.py"), silent=False)

    Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )

    db.init_app(app)

    app.secret_key = SECRET_KEY

    login_manager = LoginManager()
    login_manager.login_view = 'main.login'
    login_manager.init_app(app)

    # blueprint for non-auth parts of app
    from .app import app as main_blueprint

    app.register_blueprint(main_blueprint)

    from .callbacks import callbacks as callbacks_blueprint

    app.register_blueprint(callbacks_blueprint)

    from .user_auth import user_auth as user_auth_blueprint

    app.register_blueprint(user_auth_blueprint)

    @login_manager.user_loader
    def load_user(user_id):
        return session.get(user_id)

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("error.html", title="Page not found", error=404), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return render_template("error.html", title="Method not allowed", error=405), 405

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", title="Server error", error=500), 500

    return app