# import third-party libraries
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.routing import Mount

# import Google Cloud Logging API (third-party library)
from google.cloud import logging as gcp_logging

# import Python's standard libraries
import logging

# import local python libraries
from classes import CONSTANTS, APP_CONSTANTS, CLOUD_LOGGER
from classes.middleware import add_middleware_to_app, add_app_exception_handlers, add_api_exception_handlers
from routers import api_v1, web_app_general

"""--------------------------- Start of API Configuration ---------------------------"""

routes = [
    Mount(
        path="/static", 
        app=StaticFiles(
            directory=str(CONSTANTS.ROOT_DIR_PATH.joinpath("static"))
        ), 
        name="static_files"
    ),
    # For adding several APIs on top of the main API...
    # https://fastapi.tiangolo.com/advanced/sub-applications/
    # https://github.com/tiangolo/fastapi/issues/2806
    Mount(
        path="/api/v1", 
        app=api_v1,
        name="api_v1"
    )
]
app = FastAPI(
    debug=APP_CONSTANTS.DEBUG_MODE,
    version=APP_CONSTANTS.LATEST_VER,
    routes=routes,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    swagger_ui_oauth2_redirect_url=None
)

# add custom middleware to app and the API
add_middleware_to_app(app)
add_middleware_to_app(api_v1)

# Add custom exception handlers
add_app_exception_handlers(app=app)
add_api_exception_handlers(api=api_v1)

# Integrate Google CLoud Logging to the API
gcp_logging.handlers.setup_logging(CLOUD_LOGGER.GOOGLE_LOGGING_HANDLER)
logging.getLogger().setLevel(logging.INFO)

"""--------------------------- End of API Configuration ---------------------------"""

"""--------------------------- Start of App Routes ---------------------------"""

# For mounting the routes to the main API
# similar to Flask's Blueprint module
app.include_router(web_app_general)

"""--------------------------- End of App Routes ---------------------------"""

if (__name__ == "__main__"):
    from uvicorn import run
    run(
        "app:app", 
        host="127.0.0.1", 
        port=8080,
        reload=True, 
        debug=APP_CONSTANTS.DEBUG_MODE,
        log_level="info"
    )