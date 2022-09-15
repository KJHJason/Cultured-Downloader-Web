# import third-party libraries
import pymongo
import motor.motor_asyncio
from fastapi import Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# import python standard libraries
import time
import base64
import socket
import hashlib
import secrets
from typing import Any, Literal
from binascii import Error as BinasciiError
from classes.app_constants import APP_CONSTANTS

# import local python libraries
from classes.exceptions import APIException
from classes import CONSTANTS as C, SECRET_MANAGER, CSRF_HMAC

def format_server_time() -> str:
    """Demo function to format the server time."""
    serverTime = time.localtime()
    return time.strftime("%I:%M:%S %p", serverTime)

def get_user_ip(request: Request) -> str:
    """Returns the user's IP address as a string.

    For cloudflare proxy, we need to get from the request headers:
    https://developers.cloudflare.com/fundamentals/get-started/reference/http-request-headers/

    Args:
        request (Request): 
            The request object

    Returns:
        str:
            The user's IP address (127.0.0.1 if not found)
    """
    cloudflareProxy = request.headers.get(key="CF-Connecting-IP", default=None)
    if (cloudflareProxy is not None):
        return cloudflareProxy

    requestIP = request.client
    if (requestIP is not None):
        return requestIP.host

    return "127.0.0.1"

def format_ip_address(ip_address: str) -> bytes:
    """Formats the IP address to bytes.

    Args:
        ip_address (str):
            The IP address to format

    Returns:
        bytes:
            The IP address in bytes
    """
    try:
        return socket.inet_aton(ip_address)
    except (OSError):
        # if the IP address is ipv6
        return socket.inet_pton(socket.AF_INET6, ip_address)

def read_user_data(base64_encoded_data: str, decode: bool | None = False) -> str | bytes:
    """Reads the user data from the request.

    Args:
        base64_encoded_data (str):
            The base64 encoded data
        decode (bool):
            Whether to decode the data to a string or not

    Returns:
        str | bytes:
            The user data

    Raises:
        APIException:
            If the data could not be decoded
    """
    try:
        data = base64.b64decode(base64_encoded_data)
    except (BinasciiError, ValueError, TypeError):
        raise APIException(error="Invalid base64-encoded data.")
    return data.decode("utf-8") if (decode) else data

def get_mongodb_client() -> pymongo.MongoClient:
    """Returns an authenticated MongoDB client."""
    conn_str =  "mongodb+srv://{username}:{password}@cultured-downloader" \
                ".cjhfnzw.mongodb.net/?retryWrites=true&w=majority".format(
                    username=SECRET_MANAGER.get_secret_payload(
                        secret_id="mongodb-username"
                    ),
                    password=SECRET_MANAGER.get_secret_payload(
                        secret_id="mongodb-password"
                    )
                )

    client = motor.motor_asyncio.AsyncIOMotorClient(
        host=conn_str,
        tls=True,
        tlsInsecure=False
    )
    return client

def validate_csrf_token(request: Request, request_token: str | None = None) -> Literal[True]:
    """Validates the CSRF token.

    Args:
        request (Request):
            The request object

    Simple usage example:
    >>> @router.post("/login")
    >>> async def login(request: Request):
    >>>     validate_csrf_token(request)
    >>>     # Do login stuff here

    Usage example with a form submission:
    >>> from fastapi import Form
    >>> from pydantic import BaseModel
    >>> 
    >>> class LoginForm(BaseModel):
    >>>     username: str
    >>>     password: str
    >>>     csrf_token: str
    >>> 
    >>>     @classmethod
    >>>     def as_form(cls, username, password, csrf_token) -> AnyForm:
    >>>         return cls(username=username, password=password, csrf_token=csrf_token)
    >>> 
    >>> @router.post("/login")
    >>> async def login(form_data: LoginForm = Depends(LoginForm.as_form)):
    >>>     validate_csrf_token(request, form_data.csrf_token)
    >>>     # Do login stuff here

    Returns:
        True regardless of whether the token is valid as an 
        APIException will be raised if the token is invalid.

    Raises:
        APIException:
            If the CSRF token is invalid
    """
    csrf_token = request.cookies.get(APP_CONSTANTS.CSRF_COOKIE_NAME, None)
    if (csrf_token is None):
        raise APIException(error="Could not find CSRF cookie.")

    signed_token = request_token or request.headers.get("X-CSRF-Token", None)
    if (signed_token is None):
        raise APIException(error="CSRF token was not present in the request.")

    token = CSRF_HMAC.get(token=signed_token, default=None)
    if (token is None or token != csrf_token):
        raise APIException(error="CSRF token was invalid.")

    return True

def generate_csrf_token(request: Request, response: Response) -> str:
    """Generate a CSRF token ONLY when there is no csrf_cookie."""
    signed_token = request.cookies.get(APP_CONSTANTS.CSRF_COOKIE_NAME, None)
    hashed_token = None
    if (signed_token is not None):
        hashed_token = CSRF_HMAC.get(token=signed_token, default=None)

    if (hashed_token is None):
        hashed_token = hashlib.sha256(secrets.token_bytes(64)).hexdigest()
        signed_token = CSRF_HMAC.sign(hashed_token)
        response.set_cookie(
            key=APP_CONSTANTS.CSRF_COOKIE_NAME,
            value=signed_token,
            httponly=True,
            secure=not APP_CONSTANTS.DEBUG_MODE,
            samesite="strict",
            max_age=CSRF_HMAC.max_age
        )

    return signed_token

def get_jinja2_template_handler() -> Jinja2Templates:
    """Returns the Jinja2Templates handler object.

    Returns:
        Jinja2Templates:
            The Jinja2Templates handler object
    """
    templates = Jinja2Templates(
        directory=str(C.ROOT_DIR_PATH.joinpath("templates")), 
        trim_blocks=True,
        lstrip_blocks=True
    )
    templates.env.globals["user_ip"] = get_user_ip
    templates.env.globals["csrf_token"] = generate_csrf_token
    return templates

def render_template(templates_handler: Jinja2Templates | None = None, *args: Any, **kwargs: Any) -> HTMLResponse:
    """Renders the Jinja2 template.

    Note: This function is the same as:
    >>> templates_handler.TemplateResponse(*args, **kwargs)

    Args:
        templates_handler (Jinja2Templates):
            The Jinja2Templates handler object
            (If not provided, will obtain a new templates handler from get_jinja2_template_handler())
        *args:
            The arguments to pass to the Jinja2 template (Note: template_handler must be provided to pass in *args)
        **kwargs:
            The keyword arguments to pass to the Jinja2 template

    Returns:
        HTMLResponse:
            The rendered Jinja2 template
    """
    if (templates_handler is None):
        templates_handler = get_jinja2_template_handler()
    elif (not isinstance(templates_handler, Jinja2Templates)):
        raise TypeError("templates_handler must be an instance of Jinja2Templates.")

    return templates_handler.TemplateResponse(*args, **kwargs)