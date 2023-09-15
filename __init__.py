import os

from flask import Flask, render_template

from config import SECRET_KEY


def create_app():
    app = Flask(__name__)

    # read config.py file
    app.config.from_pyfile(os.path.join(".", "config.py"), silent=False)

    app.secret_key = SECRET_KEY

    # blueprint for non-auth parts of app
    from app import app as main_blueprint

    app.register_blueprint(main_blueprint)

    from callbacks import callbacks as callbacks_blueprint

    app.register_blueprint(callbacks_blueprint)

    from user_auth import user_auth as user_auth_blueprint

    app.register_blueprint(user_auth_blueprint)

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


if __name__ == "__main__":
    app = create_app()
    app.run()
