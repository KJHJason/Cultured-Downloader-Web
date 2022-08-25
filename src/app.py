# import flask libraries (Third-party libraries)
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask.sessions import SecureCookieSessionInterface

# import Google Cloud Logging API (third-party library)
from google.cloud import logging as gcp_logging

# import Python's standard libraries
from os import environ
import hashlib
import logging

# import local python libraries
from classes import APP_CONSTANTS as AC, SECRET_MANAGER, CLOUD_LOGGER
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

# Flask limiter config
limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per second"])

# Integrate Google CLoud Logging to the Flask app
app.config["CLOUD_LOGGER"] = CLOUD_LOGGER
gcp_logging.handlers.setup_logging(app.config["CLOUD_LOGGER"].GOOGLE_LOGGING_HANDLER)
logging.getLogger().setLevel(logging.INFO)
app.logger.addHandler(app.config["CLOUD_LOGGER"].GOOGLE_LOGGING_HANDLER)

"""--------------------------- End of Flask Configuration ---------------------------"""

"""--------------------------- Start of App Routes ---------------------------"""

with app.app_context():
    app.register_blueprint(general)
    app.register_blueprint(api)

"""--------------------------- End of App Routes ---------------------------"""

if (__name__ == "__main__"):
    host = "0.0.0.0" if (not AC.DEBUG_MODE) else None
    app.run(debug=AC.DEBUG_MODE, host=host, port=int(environ.get("PORT", 8080)))