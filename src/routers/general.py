# import third-party libraries
from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse

# import local python libraries
from functions import format_server_time, get_jinja2_template_handler, render_template
from classes import CONSTANTS, APP_CONSTANTS
from classes.responses import PrettyJSONResponse
from classes.middleware import generate_nonce

web_app_general = APIRouter(
    include_in_schema=False
)
templates_handler = get_jinja2_template_handler()

@web_app_general.get(
    path="/",
    response_class=HTMLResponse
)
async def index(request: Request):
    server_time = {"server_time": format_server_time()}
    context = {
        "request": request, 
        "csp_nonce": generate_nonce(), 
        "context": server_time
    }

    if (not APP_CONSTANTS.DEBUG_MODE):
        # Remove the code below once the frontend is ready
        return render_template(
            templates_handler,
            name="wip_page.html", 
            context=context
        )
    else:
        return render_template(
            templates_handler,
            name="general/index.html",
            context=context
        )

@web_app_general.get("/favicon.ico")
async def favicon():
    """Return the favicon of the web app."""
    generate_nonce()
    return FileResponse(CONSTANTS.ICON_PATH)

@web_app_general.get(
    path="/418",
    response_class=PrettyJSONResponse, 
    status_code=418
)
async def teapot(request: Request):
    generate_nonce()
    return render_template(
        templates_handler,
        name="error.html", 
        context={
            "request": request, 
            "csp_nonce": generate_nonce(),
            "status_code": 418,
            "title": "I'm a teapot!",
            "description": "I'm a teapot"
        },
        status_code=418
    )

if (APP_CONSTANTS.DEBUG_MODE):
    @web_app_general.get(
        path="/api/latest/docs",
        response_class=RedirectResponse
    )
    async def latest_docs():
        generate_nonce()
        return RedirectResponse(url=f"/api/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.DOCS_URL}")

@web_app_general.get(
    path="/api",
    response_class=RedirectResponse
)
@web_app_general.get(
    path="/api/latest/redoc",
    response_class=RedirectResponse
)
async def latest_redocs():
    generate_nonce()
    return RedirectResponse(url=f"/api/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.REDOC_URL}")

@web_app_general.get(
    path="/api/latest/openapi.json",
    response_class=RedirectResponse
)
async def latest_openapi_json():
    generate_nonce()
    return RedirectResponse(url=f"/api/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.OPENAPI_JSON_URL}")