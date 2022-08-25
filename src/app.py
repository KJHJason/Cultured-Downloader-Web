# import flask libraries (Third-party libraries)
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask.sessions import SecureCookieSessionInterface

# import Python's standard libraries
from os import environ
import hashlib

# import local python libraries
from classes import CONSTANTS as C, SECRET_MANAGER
from routes import general, api

"""--------------------------- Start of Flask Configuration ---------------------------"""

app = Flask(__name__)

# Maximum file size for uploading anything to the web app's server
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024 # 1MiB

# Flask session cryptographic configurations
app.config["SECRET_KEY"] = SECRET_MANAGER.get_secret_payload(
    secretID="flask-secret-key", decodeSecret=False
)
FLASK_SESSION_COOKIE_INTERFACE = SecureCookieSessionInterface()
FLASK_SESSION_COOKIE_INTERFACE.salt = SECRET_MANAGER.get_secret_payload(
    secretID="flask-session-salt", decodeSecret=False
)
FLASK_SESSION_COOKIE_INTERFACE.digest_method = staticmethod(hashlib.sha512)
app.session_interface = FLASK_SESSION_COOKIE_INTERFACE

# Flask session cookie configurations
app.config["SESSION_PERMANENT"] = False # Session cookie will be deleted when the browser is closed

limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per second"])

"""--------------------------- End of Flask Configuration ---------------------------"""

"""--------------------------- Start of App Routes ---------------------------"""

with app.app_context():
    app.register_blueprint(general)
    app.register_blueprint(api)

"""--------------------------- End of App Routes ---------------------------"""

if (__name__ == "__main__"):
    host = "0.0.0.0" if (not C.DEBUG_MODE) else None
    app.run(debug=C.DEBUG_MODE, host=host, port=int(environ.get("PORT", 8080)))