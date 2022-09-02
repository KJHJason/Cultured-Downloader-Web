# import third-party libraries
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

# import local python libraries
from functions import get_user_ip
from functions.v1 import format_gdrive_json_response, format_file_json_responses, \
                         format_directory_json_response, format_directory_json_responses
from classes import USER_DATA, GoogleDrive, APP_CONSTANTS, CLOUD_LOGGER
from classes.responses import PrettyJSONResponse
from classes.middleware import generate_nonce, exempt_csp
from classes.v1 import  UserDataJsonRequest, UserDataJsonResponse, \
                        GDriveJsonRequest, PublicKeyResponse, PublicKeyRequest
from classes.exceptions import CRC32ChecksumError, DecryptionError, APIException

# import Python's standard libraries
import asyncio

api = FastAPI(
    debug=APP_CONSTANTS.DEBUG_MODE,
    title="Cultured Downloader API",
    version=APP_CONSTANTS.VER_ONE,
    docs_url=None,
    redoc_url=None,
    openapi_url=APP_CONSTANTS.OPENAPI_JSON_URL,
    swagger_ui_oauth2_redirect_url=None,
    responses=APP_CONSTANTS.API_RESPONSES
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
        "main_website": "https://cultureddownloader.com/",
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

@api.post(
    path="/public-key",
    description="Get the public key for secure communication when transmitting the user's data on top of HTTPS",
    summary="Available algorithm: RSA4096-OAEP-SHA512, RSA4096-OAEP-SHA256",
    response_model=PublicKeyResponse,
    response_class=PrettyJSONResponse,
    include_in_schema=True
)
async def get_public_key(request: Request, json_payload: PublicKeyRequest):
    generate_nonce()
    algorithm = json_payload.algorithm.lower()

    CLOUD_LOGGER.info(
        content=f"User {get_user_ip(request)}: Retrieved the public key (algorithm: {algorithm})]"
    )

    # if (algorithm == "rsa"):  # commented it out since only RSA is supported and the
                                # path parameter will be validated via the PublicKeyRequest class
    return {"public_key": USER_DATA.get_api_rsa_public_key(digest_method=json_payload.digest_method)}

@api.post(
    path="/encrypt", 
    description="Encrypts the user's data with the server's symmetric key",
    response_model=UserDataJsonResponse,
    response_class=PrettyJSONResponse,
    include_in_schema=True
)
async def encrypt_cookie(request: Request, json_payload: UserDataJsonRequest):
    generate_nonce()
    CLOUD_LOGGER.info(
        content={
            "message": f"User {get_user_ip(request)}: Encrypted their data.",
            "data": "REDACTED",
            "data_type": str(type(json_payload.data)),
            "public_key": json_payload.public_key,
            "digest_method": json_payload.digest_method,
        }
    )

    data_payload = USER_DATA.decrypt_user_payload(
        encrypted_data=json_payload.data, 
        digest_method=json_payload.digest_method
    )
    if ("error" in data_payload):
        raise APIException(error=data_payload)

    try:
        encrypted_user_data = USER_DATA.encrypt_user_data(
            user_data=data_payload["payload"],
            user_public_key=json_payload.public_key,
            digest_method=json_payload.digest_method
        )
    except (CRC32ChecksumError):
        raise APIException(error="integrity checks failed.")

    return {"data": encrypted_user_data}

@api.post(
    path="/decrypt",
    description="Decrypts the user's data with the server's symmetric key",
    response_model=UserDataJsonResponse,
    response_class=PrettyJSONResponse,
    include_in_schema=True
)
async def decrypt_cookie(request: Request, json_payload: UserDataJsonRequest):
    generate_nonce()
    CLOUD_LOGGER.info(
        content={
            "message": f"User {get_user_ip(request)}: Decrypted their data.",
            "data": "REDACTED",
            "data_type": str(type(json_payload.data)),
            "public_key": json_payload.public_key,
            "digest_method": json_payload.digest_method,
        }
    )

    encrypted_data_payload = USER_DATA.decrypt_user_payload(
        encrypted_data=json_payload.data, 
        digest_method=json_payload.digest_method
    )
    if ("error" in encrypted_data_payload):
        raise APIException(error=encrypted_data_payload)

    try:
        decrypted_user_data = USER_DATA.decrypt_user_data(
            encrypted_user_data=encrypted_data_payload["payload"], 
            user_public_key=json_payload.public_key,
            digest_method=json_payload.digest_method
        )
    except (TypeError):
        raise APIException(error="encrypted cookie must be in bytes.")
    except (CRC32ChecksumError):
        raise APIException(error="integrity checks failed, please try again.")
    except (DecryptionError):
        raise APIException(error="decryption failed.")

    return {"data": decrypted_user_data}