# import third-party libraries
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# import python standard libraries
import time
from typing import Any

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