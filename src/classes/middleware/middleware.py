# import third-party libraries
from fastapi import Request, Response
from fastapi.responses import HTMLResponse
from fastapi.exceptions import RequestValidationError, HTTPException
from starlette.types import ASGIApp
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.exceptions import HTTPException as StarletteHTTPException
from Secweb.xXSSProtection import xXSSProtection
from Secweb.StrictTransportSecurity import HSTS
from Secweb.XFrameOptions import XFrame
from Secweb.XContentTypeOptions import XContentTypeOptions
from Secweb.ReferrerPolicy import ReferrerPolicy

# import Python's standard libraries
import json
import re

# import local python libraries
from classes.cloud_logger import CLOUD_LOGGER
from classes.app_constants import APP_CONSTANTS as AC
from classes.exceptions import APIException
from classes.responses import PrettyJSONResponse
from functions import get_jinja2_template_handler
from .csp_middleware import ContentSecurityPolicy
from .jwt_middleware import AuthlibJWTMiddleware, API_HMAC

class CacheControlURLRule:
    """Creates an object that contains the path and cache control headers for a route"""
    def __init__(self, path: str, cache_control: str) -> None:
        """Configure the cache control headers for a particular route URL

        Attributes:
            path (str|re.Pattern): 
                The url path of the route
            cache_control (str): 
                The cache control headers for the route
        """
        self.__path = path
        self.__cache_control = cache_control

    @property
    def path(self) -> str | re.Pattern:
        """The url path of the route"""
        return self.__path

    @property
    def cache_control(self) -> str:
        """The cache control headers for the route"""
        return self.__cache_control

class CacheControlMiddleware(BaseHTTPMiddleware):
    """Adds a Cache-Control header to the specified API routes.
    With reference to: https://github.com/attakei/fastapi-simple-cache_control"""
    def __init__(self, app: ASGIApp, routes: tuple[CacheControlURLRule] | list[CacheControlURLRule]) -> None:
        """Adds a Cache-Control header to the specified API routes.

        Attributes:
            cache_control (str):
                The cache-control header value
            routes (tuple | list):
                The API routes to add the cache-control header to
        """
        routes_rule = []
        for route in routes:
            if (isinstance(route, CacheControlURLRule)):
                routes_rule.append(route)
            else:
                raise TypeError(f"Invalid route type: {type(route)}")

        self.__routes = tuple(routes_rule)
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        user_req_path = request.url.path
        for route in self.__routes:
            if (
                (isinstance(route.path, str) and user_req_path == route.path) ^ 
                (isinstance(route.path, re.Pattern) and route.path.match(user_req_path) is not None)
            ):
                response.headers["Cache-Control"] = route.cache_control
                break
        else:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

def add_middleware_to_app(app: ASGIApp):
    """Adds custom middleware to the API"""
    # add session capability to the API similar to
    # flask session, request.session["key"] = "value"
    app.add_middleware(
        AuthlibJWTMiddleware, 
        jwt_obj=API_HMAC,
        https_only=AC.DEBUG_MODE
    )
    app.add_middleware(
        xXSSProtection,
        Option={"X-XSS-Protection": "1; mode=block"}
    )
    app.add_middleware(
        XFrame,
        Option={"X-Frame-Options": "DENY"} # change to SAMEORIGIN if required
    )
    app.add_middleware(XContentTypeOptions)
    app.add_middleware(
        ReferrerPolicy,
        Option={"Referrer-Policy": "strict-origin-when-cross-origin"}
    )
    if (not AC.DEBUG_MODE):
        app.add_middleware(
            HSTS,
            Option={
                "max-age": 31536000, 
                "includeSubDomains": True, 
                "preload": True
            }
        )
        # Add CSP middleware if not in debug mode
        # since the error message uses inline css/scripts.
        app.add_middleware(
            ContentSecurityPolicy,
            style_nonce=True,
            script_nonce=True,
            csp_options={
                "style-src": [
                    "'self'",
                    "https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css",
                    "https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui.css",
                    "https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700"
                ],
                "frame-src":[
                    "'self'"
                ],
                "script-src":[
                    "'self'",
                    "https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.min.js",
                    "https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui-bundle.js",
                    "https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"
                ],
            }
        )

    # Add cache headers to the specified routes
    # when the app is not in debug mode
    if (not AC.DEBUG_MODE):
        ONE_YEAR_CACHE = "public, max-age=31536000"
        ONE_DAY_CACHE = "public, max-age=86400"
        app.add_middleware(
            CacheControlMiddleware, 
            routes=(
                CacheControlURLRule(path="/", cache_control=ONE_DAY_CACHE),
                CacheControlURLRule(path="/favicon.ico", cache_control=ONE_YEAR_CACHE),
                CacheControlURLRule(path=re.compile(r"^\/v1\/(rsa)\/public-key$"), cache_control=ONE_DAY_CACHE),
                CacheControlURLRule(path=re.compile(r"^\/v\d+\/docs$"), cache_control=ONE_DAY_CACHE),
                CacheControlURLRule(path=re.compile(r"^\/v\d+\/redoc$"), cache_control=ONE_DAY_CACHE),
                CacheControlURLRule(path=re.compile(r"^\/v\d+\/openapi\.json$"), cache_control=ONE_DAY_CACHE)
            )
        )

def add_api_exception_handlers(api: ASGIApp) -> None:
    """Adds custom exception handlers to the API"""
    @api.exception_handler(APIException)
    async def api_bad_request_handler(request: Request, exc: APIException) -> PrettyJSONResponse:
        return PrettyJSONResponse(content=exc.error, status_code=exc.status_code)

    @api.exception_handler(RequestValidationError)
    async def request_validation_error_handler(request: Request, exc: RequestValidationError) -> PrettyJSONResponse:
        errors = exc.errors()
        CLOUD_LOGGER.error(
            content={
                "Request validation error": json.dumps(obj=errors, indent=4)
            }
        )
        return PrettyJSONResponse(
            content={"error": errors}, 
            status_code=422
        )

    @api.exception_handler(HTTPException)
    @api.exception_handler(StarletteHTTPException)
    async def custom_http_exception_handler(
        request: Request, exc: HTTPException | StarletteHTTPException) -> PrettyJSONResponse:
        status_code = exc.status_code
        if (status_code == 500):
            CLOUD_LOGGER.error(
                content={
                    "HTTP Exception": json.dumps(obj=exc.detail)
                }
            )
        return PrettyJSONResponse(
            content={"error_code": status_code, "message": exc.detail},
            status_code=status_code
        )

def add_app_exception_handlers(app: ASGIApp) -> None:
    """Adds custom exception handlers to the web application"""
    templates = get_jinja2_template_handler()

    @app.exception_handler(HTTPException)
    @app.exception_handler(StarletteHTTPException)
    async def custom_error_handler(request: Request, exc: HTTPException | StarletteHTTPException) -> HTMLResponse:
        status_code = exc.status_code
        title = f"Uh Oh, Something Went Wrong!"
        description = "Something went wrong"
        if (status_code == 404):
            title = "404 - Page Not Found"
            description = "The requested resource was not found"
        elif (status_code == 500):
            CLOUD_LOGGER.error(
                content={
                    "HTTP Exception": json.dumps(obj=exc.detail)
                }
            )
            title = "500 - Internal Server Error"
            description = "Internal server error"
        elif (status_code == 418):
            title = "I'm a teapot!"
            description = "I'm a teapot"

        return templates.TemplateResponse(
            name="error.html", 
            context={
                "request": request,
                "status_code": status_code,
                "title": title.title(),
                "description": description.title()
            }
        )