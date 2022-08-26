# import flask libraries (Third-party libraries)
from flask import request, abort, current_app, wrappers
from flask_limiter.util import get_remote_address

# import Python's standard libraries
import re

def get_user_ip() -> str:
    """Returns the user's IP address as a string.

    For cloudflare proxy, we need to get from the request headers:
    https://developers.cloudflare.com/fundamentals/get-started/reference/http-request-headers/
    """
    return request.headers.get("CF-Connecting-IP") or get_remote_address()

@current_app.before_request
def before_request() -> None:
    """This function will be executed before every request."""
    if (request.endpoint is None):
        abort(404)

@current_app.after_request
def after_request(response: wrappers.Response) -> wrappers.Response:
    """This function will be executed after every request."""
    if (not current_app.config["APP_CONSTANTS"].DEBUG_MODE):
        if (request.endpoint == "static"):
            # cache static files for 1 year
            response.headers["Cache-Control"] = "public, max-age=31536000"
        elif (re.fullmatch(current_app.config["APP_CONSTANTS"].BLUEPRINT_ENDPOINT_REGEX, request.endpoint)):
            # if endpoint is the general blueprint endpoint, cache for 1 hour
            blueprintEndpoint = request.endpoint.split(sep=".", maxsplit=1)[0]
            if (blueprintEndpoint == "general"):
                response.headers["Cache-Control"] = "public, max-age=3600"

    return response