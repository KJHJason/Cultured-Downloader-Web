# import third-party libraries
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.exceptions import RequestValidationError, HTTPException
from starlette.types import ASGIApp
from starlette.exceptions import HTTPException as StarletteHTTPException
from Secweb.xXSSProtection import xXSSProtection
from Secweb.StrictTransportSecurity import HSTS
from Secweb.XFrameOptions import XFrame
from Secweb.XContentTypeOptions import XContentTypeOptions
from Secweb.ReferrerPolicy import ReferrerPolicy

# import Python's standard libraries
import re
import json

# import local python libraries
from classes.cloud_logger import CLOUD_LOGGER
from classes.app_constants import APP_CONSTANTS as AC
from classes.exceptions import APIException
from classes.responses import PrettyJSONResponse
from functions import render_template
from classes.middleware.csp_middleware import ContentSecurityPolicy
from classes.api_hmac import API_HMAC
from classes.middleware import SessionMiddleware
from classes.middleware.cache_control_middleware import CacheControlMiddleware, CacheControlURLRule

def add_middleware_to_app(app: ASGIApp):
    """Adds custom middleware to the API"""
    # add session capability to the API similar to
    # flask session, request.session["key"] = "value"
    app.add_middleware(
        SessionMiddleware, 
        signer=API_HMAC,
        https_only=not AC.DEBUG_MODE,
        max_age=3600 * 24 * 14
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
        # add HSTS header to the application
        # to force the browser to use HTTPS
        # for all requests to prevent MITM attacks
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
                    "https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css"
                ],
                "frame-src":[
                    "'self'"
                ],
                "script-src":[
                    "'self'",
                    "https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.min.js"
                ],
            }
        )

        # Add cache headers to the specified routes
        # when the app is not in debug mode
        ONE_YEAR_CACHE = "public, max-age=31536000"
        ONE_DAY_CACHE = "public, max-age=86400"
        THIRTY_MIN_CACHE = "public, max-age=1800"
        app.add_middleware(
            CacheControlMiddleware, 
            routes=(
                CacheControlURLRule(path="/", cache_control=ONE_YEAR_CACHE),
                CacheControlURLRule(path="/favicon.ico", cache_control=ONE_YEAR_CACHE),
                CacheControlURLRule(path=re.compile(r"^/static/.*$"), cache_control=ONE_YEAR_CACHE),
                CacheControlURLRule(path=re.compile(r"^/api/v\d+/redoc$"), cache_control=ONE_DAY_CACHE),
                CacheControlURLRule(path=re.compile(r"^/api/v\d+/openapi\.json$"), cache_control=ONE_DAY_CACHE),
                CacheControlURLRule(path=re.compile(r"^/api/v\d+/software/latest/file$", cache_control=THIRTY_MIN_CACHE)),
                CacheControlMiddleware(path=re.compile(r"^/api/v\d+/software/latest/version$", cache_control=ONE_DAY_CACHE)),
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

        return render_template(
            name="error.html", 
            context={
                "request": request,
                "status_code": status_code,
                "title": title.title(),
                "description": description.title()
            },
            status_code=status_code
        )