# import third-party libraries
from pydantic import BaseModel
from fastapi import Request, Response
from starlette.types import ASGIApp
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# import Python's standard libraries
import secrets

def exempt_csp(response: Response) -> None:
    """Exempt the response from the Content Security Policy middleware.

    Args:
        response (Response): 
            The response to be exempted from the Content Security Policy.

    Returns:
        None
    """
    response.headers["X-Exempt-CSP"] = "1"

nonce = None
def generate_nonce(n_bytes: int=32) -> str:
    """Generate a random nonce string for inline scripts or styles.

    Args:
        n_bytes (int, optional): 
        The number of bytes to generate. Defaults to 32.

    Returns:
        str: 
            The generated nonce string.
    """
    global nonce
    nonce = secrets.token_urlsafe(n_bytes)
    return nonce

class ContentSecurityPolicySchema(BaseModel):
    """To validate the CSP dictionary"""
    values: dict[str, list[str]]

# reference: 
#   https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
available_policies = [
    "child-src", "connect-src", "default-src", "font-src", "frame-src", "img-src", "manifest-src", 
    "media-src", "object-src", "prefetch-src", "script-src", "script-src-elem", "script-src-attr", 
    "style-src", "style-src-elem", "style-src-attr", "worker-src", "base-uri", "plugin-types", "sandbox", 
    "form-action", "frame-ancestors", "navigate-to", "report-uri", "report-to", "block-all-mixed-content", 
    "require-sri-for", "require-trusted-types-for", "trusted-types", "upgrade-insecure-requests"
]
class ContentSecurityPolicy(BaseHTTPMiddleware):
    """ContentSecurityPolicy class constructs a CSP header for the application after each requests.

    To add the middleware:
    >>> app.add_middleware(
            ContentSecurityPolicy, 
            script_nonce=True, 
            style_nonce=True,
            csp_options={"script-src": ["'self'"]}
        )

    To get the CSP nonce for passing it to jinja2 templates:
    >>> nonce = generate_nonce()
    >>> return templates.TemplateResponse(
        name="index.html", 
        context={"request": request, "csp_nonce": nonce}
    )

    To exempt a route from CSP, add a "X-CSP-Exempt" header to the response.
    >>> from fastapi import Response
    >>> from fastapi.responses import JSONResponse
    >>> from csp_middleware import exempt_csp
    >>>
    >>> async def index(response: Response):
    >>>     exempt_csp(response) # or response.headers["X-CSP-Exempt"] = "1"
    >>>     return JSONResponse({"Message": "Hello, world!"}, headers=response.headers)
    """
    def __init__(self, 
        app: ASGIApp, 
        script_nonce: bool | None = False, 
        style_nonce: bool | None = False, 
        csp_options: dict | None = {
            "default-src": ["'self'"], 
            "base-uri": ["'self'"], 
            "block-all-mixed-content": [], 
            "font-src": ["'self'", 'https:', 'data:'], 
            "frame-ancestors": ["'self'"], 
            "img-src": ["'self'", 'data:'], 
            "object-src": ["'none'"], 
            "script-src": ["'self'"], 
            "script-src-attr": ["'none'"], 
            "style-src": ["'self'", "https:", "'unsafe-inline'"], 
            "upgrade-insecure-requests": [], 
            "require-trusted-types-for": ["'script'"]
        }
    ) -> None:
        """Constructor for ContentSecurityPolicy class

        Attributes:
            app (ASGIApp): 
                The ASGI application instance
            script_nonce (bool | None, optional):
                Whether to add nonce to script-src or not. Defaults to False.
            style_nonce (bool | None, optional):
                Whether to add nonce to style-src or not. Defaults to False.
            csp_options (dict | None, optional):
                The CSP options to be used.
        """
        self.csp_options = ContentSecurityPolicySchema(values=csp_options)
        for csp_option in self.csp_options.values:
            if (csp_option not in available_policies):
                raise SyntaxError(f"CSP option, \"{csp_option}\", does not exists.")

        if (script_nonce and "script-src" not in self.csp_options.values):
            raise SyntaxError("CSP option, \"script-src\", does not exists but script_nonce is set to True.")
        if (script_nonce and len(self.csp_options.values["script-src"]) == 0):
            raise SyntaxError("CSP option, \"script-src\", cannot be empty.")

        if (style_nonce and "style-src" not in self.csp_options.values):
            raise SyntaxError("CSP option, \"style-src\", does not exists but style_nonce is set to True.")
        if (style_nonce and len(self.csp_options.values["style-src"]) == 0):
            raise SyntaxError("CSP option, \"style-src\", cannot be empty.")

        self.script_nonce = script_nonce
        self.style_nonce = style_nonce
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        exempt_csp = response.headers.get(key="X-Exempt-CSP", default=False)
        if (exempt_csp != "1"):
            parsed_csp = ""
            for key, value in self.csp_options.values.items():
                append_nonce = False
                if ((self.script_nonce and key == "script-src") or (self.style_nonce and key == "style-src")):
                    append_nonce = True
                parsed_csp += "{key}{nonce}{values}; ".format(
                    key=key,
                    values=f" {' '.join(value)}" if (len(value) > 0) else "",
                    nonce=f" 'nonce-{nonce}'" if (append_nonce) else ""
                )
            response.headers["Content-Security-Policy"] = parsed_csp

        return response