# import third-party libraries
from fastapi import Request
from fastapi.templating import Jinja2Templates

# import python standard libraries
import time

# import local python libraries
from classes import CONSTANTS as C

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
    templates.env.globals.update(
        get_user_ip=get_user_ip
    )
    return templates