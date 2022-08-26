# import flask libraries (Third-party libraries)
from flask import Flask
from flask_talisman import Talisman
from flask.sessions import SecureCookieSessionInterface

# import Google Cloud Logging API (third-party library)
from google.cloud import logging as gcp_logging

# import Python's standard libraries
from os import environ
import hashlib
import logging

# import local python libraries
from classes import APP_CONSTANTS as AC, SECRET_MANAGER, CLOUD_LOGGER

"""--------------------------- Start of Flask Configuration ---------------------------"""

app = Flask(__name__)
app.config["APP_CONSTANTS"] = AC

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
with app.app_context():
    from routes import LIMITER
    LIMITER.init_app(app)

# Flask talisman for security purposes
TALISMAN = Talisman(
    app=app,

    # The web application's policies
    permissions_policy={
        "geolocation": "()",
        "microphone": "()"
    },

    # CSP configurations
    content_security_policy={
        "style-src": [
            "'self'",
            "https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css"
        ],
        "frame-src":[
            "'self'"
        ],
        "script-src":[
            "'self'",
            "https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.min.js"
        ]
    },
    content_security_policy_nonce_in=["script-src"],

    # XSS protection configuration
    # to prevent reflected XSS attacks
    x_xss_protection=True, # Will require nonce="{{ csp_nonce() }}" in script tags

    # HTTPS configurations to redirect
    # HTTP requests to use HTTPS
    # Note: This is still vulnerable to MITM attacks
    force_https=True, # Note: Will be disabled in debug mode
    force_https_permanent=True,

    # HSTS configurations to tell the browser
    # to automatically use HTTPS for the next 1 year
    # to prevents MITM attacks.
    # Note: HSTS is also enabled on our custom domain via Cloudflare
    strict_transport_security=True,
    strict_transport_security_preload=True,
    strict_transport_security_max_age=31536000, # 1 year
    strict_transport_security_include_subdomains=True,

    # Flask session cookie configurations
    session_cookie_secure=True, # Note: Will be disabled in debug mode
    session_cookie_http_only=True,
    session_cookie_samesite="Lax"
)

# Integrate Google CLoud Logging to the Flask app
app.config["CLOUD_LOGGER"] = CLOUD_LOGGER
gcp_logging.handlers.setup_logging(app.config["CLOUD_LOGGER"].GOOGLE_LOGGING_HANDLER)
logging.getLogger().setLevel(logging.INFO)
app.logger.addHandler(app.config["CLOUD_LOGGER"].GOOGLE_LOGGING_HANDLER)

"""--------------------------- End of Flask Configuration ---------------------------"""

"""--------------------------- Start of App Routes ---------------------------"""

with app.app_context():
    from routes import general, api
    app.register_blueprint(general)
    app.register_blueprint(api)

"""--------------------------- End of App Routes ---------------------------"""

if (__name__ == "__main__"):
    host = "0.0.0.0" if (not AC.DEBUG_MODE) else None
    app.run(debug=AC.DEBUG_MODE, host=host, port=int(environ.get("PORT", 8080)))