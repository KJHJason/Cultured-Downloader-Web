# import third-party libraries
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

# import local python libraries
from functions import get_user_ip
from functions.v1 import format_gdrive_json_response, format_file_json_responses, \
                         format_directory_json_response, format_directory_json_responses
from classes import GoogleDrive, APP_CONSTANTS, CLOUD_LOGGER
from classes.responses import PrettyJSONResponse
from classes.middleware import generate_nonce, exempt_csp
from classes.v1 import GDriveJsonRequest

# import Python's standard libraries
import asyncio
from typing import Any

api = FastAPI(
    debug=APP_CONSTANTS.DEBUG_MODE,
    title="Cultured Downloader API",
    description="""An API by <a href='https://github.com/KJHJason'>KJHJason</a> to help users like you 
with batch downloading content from Pixiv Fanbox and Fantia.\n
However, it is recommended that you create your own Google Drive API key and use it as this API is rate limited by Google.\n
Note: The user must be logged in to the services mentioned in order to download any paid content.\n
Check out the main software at <a href='https://github.com/KJHJason/Cultured-Downloader'>GitHub</a>.""",
    version=APP_CONSTANTS.VER_ONE,
    docs_url=None,
    redoc_url=None,
    openapi_url=APP_CONSTANTS.OPENAPI_JSON_URL,
    swagger_ui_oauth2_redirect_url=None
)

@api.get(
    path="/",
    response_class=PrettyJSONResponse,
    include_in_schema=False
)
async def index():
    generate_nonce()
    return {
        "message": "Welcome to Cultured Downloader API!",
        "latest_version": APP_CONSTANTS.LATEST_VER,
        "bug_reports": "https://github.com/KJHJason/Cultured-Downloader/issues"
    }

if (APP_CONSTANTS.DEBUG_MODE):
    @api.get(
        path=APP_CONSTANTS.DOCS_URL,
        response_class=HTMLResponse,
        include_in_schema=False
    )
    async def swagger_ui_html(response: Response):
        html_response = get_swagger_ui_html(
            openapi_url=APP_CONSTANTS.VER_ONE_OPENAPI_JSON_URL,
            title=f"{api.title} - Swagger UI",
            oauth2_redirect_url=None,
            init_oauth=api.swagger_ui_init_oauth,
            swagger_favicon_url=APP_CONSTANTS.FAVICON_URL,
            swagger_ui_parameters=api.swagger_ui_parameters,
        )
        exempt_csp(response)
        html_response.init_headers(response.headers)
        return html_response

@api.get(
    path=APP_CONSTANTS.REDOC_URL,
    response_class=HTMLResponse,
    include_in_schema=False
)
async def redoc_html(response: Response):
    html_response = get_redoc_html(
        openapi_url=APP_CONSTANTS.VER_ONE_OPENAPI_JSON_URL,
        title=f"{api.title} - ReDoc",
        redoc_favicon_url=APP_CONSTANTS.FAVICON_URL
    )
    exempt_csp(response)
    html_response.init_headers(response.headers)
    return html_response

@api.post(
    path="/drive/query",
    description="Query Google Drive API to get the file details or all the files in a folder. Note that files or folders that has a resource key will not work and will return an empty JSON response.",
    response_class=PrettyJSONResponse,
    response_model=Any,
    include_in_schema=True
)
async def google_drive_query(request: Request, data_payload: GDriveJsonRequest):
    generate_nonce()
    query_id = data_payload.drive_id
    gdrive_type = data_payload.attachment_type

    CLOUD_LOGGER.info(
        content=f"User {get_user_ip(request)}: Queried [{gdrive_type}, {query_id}]"
    )

    gdrive = GoogleDrive()
    request_headers = APP_CONSTANTS.DRIVE_REQ_HEADERS.copy()
    request_headers["Authorization"] = f"Bearer {gdrive.get_oauth_access_token()}"
    if (gdrive_type == "file"):
        if (isinstance(query_id, str)):
            file_details = await gdrive.get_file_details(file_id=query_id, headers=request_headers)
            return format_gdrive_json_response(file_details)
        else:
            file_arr = await asyncio.gather(*[
                gdrive.get_file_details(file_id=file_id, headers=request_headers) for file_id in query_id
            ])
            return format_file_json_responses(file_arr)
    else:
        if (isinstance(query_id, str)):
            directory_content = await gdrive.get_folder_contents(folder_id=query_id, headers=request_headers)
            return format_directory_json_response(directory_content)
        else:
            directory_arr = await asyncio.gather(*[
                gdrive.get_folder_contents(folder_id=folder_id, headers=request_headers) for folder_id in query_id
            ])
            return format_directory_json_responses(directory_arr)