# import local python libraries
from .utils import get_user_ip

# import flask libraries (Third-party libraries)
from flask_limiter import Limiter
from flask import current_app

LIMITER = Limiter(
    key_func=get_user_ip, 
    default_limits=[current_app.config["APP_CONSTANTS"].DEFAULT_REQUEST_LIMIT]
)