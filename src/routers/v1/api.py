# import third-party libraries
import bson
import pymongo.errors as pymongo_errors
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

# import local python libraries
from functions import   get_user_ip, generate_csrf_token, validate_csrf_token, \
                        get_mongodb_client, format_ip_address, read_user_data
from functions.v1 import format_gdrive_json_response, format_file_json_responses, \
                         format_directory_json_response, format_directory_json_responses
from classes import GoogleDrive, APP_CONSTANTS as AC, CLOUD_LOGGER, AESGCM, USER_DATA
from classes.exceptions import APIException
from classes.responses import PrettyJSONResponse
from classes.middleware import generate_nonce, exempt_csp, API_HMAC
from classes.v1 import  GDriveJsonRequest, CsrfResponse, SaveKeyRequest, SaveKeyResponse, \
                        PublicKeyResponse, PublicKeyRequest, GetKeyRequest, GetKeyResponse

# import Python's standard libraries
import time
import hashlib
import asyncio
import secrets
import base64
from typing import Any
from datetime import datetime

api = FastAPI(
    debug=AC.DEBUG_MODE,
    title="Cultured Downloader API",
    description="""An API by <a href='https://github.com/KJHJason'>KJHJason</a> to help users like you 
with batch downloading content from Pixiv Fanbox and Fantia.\n
However, it is recommended that you create your own Google Drive API key and use it as this API is rate limited by Google.\n
The user can also use this API to securely store their secret key in the server's database for future use.\n
Additionally, the API can handle key rotations for the user because the saved key will expire after a month as compared to the user's locally stored key which are valid forever.\n
Note: The user must be logged in to the services mentioned in order to download any paid content.\n
Check out the main software at <a href='https://github.com/KJHJason/Cultured-Downloader'>GitHub</a>.""",
    version=AC.VER_ONE,
    docs_url=None,
    redoc_url=None,
    openapi_url=AC.OPENAPI_JSON_URL,
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
        "latest_version": AC.LATEST_VER,
        "bug_reports": "https://github.com/KJHJason/Cultured-Downloader/issues"
    }

if (AC.DEBUG_MODE):
    @api.get(
        path=AC.DOCS_URL,
        response_class=HTMLResponse,
        include_in_schema=False
    )
    async def swagger_ui_html(response: Response):
        html_response = get_swagger_ui_html(
            openapi_url=AC.VER_ONE_OPENAPI_JSON_URL,
            title=f"{api.title} - Swagger UI",
            oauth2_redirect_url=None,
            init_oauth=api.swagger_ui_init_oauth,
            swagger_favicon_url=AC.FAVICON_URL,
            swagger_ui_parameters=api.swagger_ui_parameters,
        )
        exempt_csp(response)
        html_response.init_headers(response.headers)
        return html_response

@api.get(
    path=AC.REDOC_URL,
    response_class=HTMLResponse,
    include_in_schema=False
)
async def redoc_html(response: Response):
    html_response = get_redoc_html(
        openapi_url=AC.VER_ONE_OPENAPI_JSON_URL,
        title=f"{api.title} - ReDoc",
        redoc_favicon_url=AC.FAVICON_URL
    )
    exempt_csp(response)
    html_response.init_headers(response.headers)
    return html_response

@api.post(
    path="/drive/query",
    description="Query Google Drive API to get the file details or all the files in a folder. Note that files or folders that has a resource key will not work and will return an empty JSON response.",
    response_class=PrettyJSONResponse,
    response_model=Any
)
async def google_drive_query(request: Request, data_payload: GDriveJsonRequest):
    generate_nonce()
    query_id = data_payload.drive_id
    gdrive_type = data_payload.attachment_type

    CLOUD_LOGGER.info(
        content=f"User {get_user_ip(request)}: Queried [{gdrive_type}, {query_id}]"
    )

    gdrive = GoogleDrive()
    request_headers = AC.DRIVE_REQ_HEADERS.copy()
    request_headers["Authorization"] = f"Bearer {gdrive.get_oauth_access_token()}"
    if (gdrive_type == "file"):
        if (isinstance(query_id, str)):
            file_details = await gdrive.get_file_details(
                file_id=query_id,
                headers=request_headers
            )
            return format_gdrive_json_response(file_details)
        else:
            file_arr = await asyncio.gather(*[
                gdrive.get_file_details(
                    file_id=file_id, 
                    headers=request_headers
                ) 
                for file_id in query_id
            ])
            return format_file_json_responses(file_arr)
    else:
        if (isinstance(query_id, str)):
            directory_content = await gdrive.get_folder_contents(
                folder_id=query_id,
                headers=request_headers
            )
            return format_directory_json_response(directory_content)
        else:
            directory_arr = await asyncio.gather(*[
                gdrive.get_folder_contents(
                    folder_id=folder_id, 
                    headers=request_headers
                ) 
                for folder_id in query_id
            ])
            return format_directory_json_responses(directory_arr)

@api.get(
    path="/csrf-token",
    description="Returns a CSRF token for the user to use in a request, if required.",
    response_model=CsrfResponse,
    response_class=PrettyJSONResponse,
)
async def get_csrf_token(request: Request):
    generate_nonce()
    return {"csrf_token": generate_csrf_token(request)}

@api.post(
    path="/public-key",
    description="Get the public key for secure communication when transmitting the user's data on top of HTTPS."
                "\n\nAvailable algorithm: RSA4096-OAEP-SHA512, RSA4096-OAEP-SHA256",
    response_model=PublicKeyResponse,
    response_class=PrettyJSONResponse
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
    path="/save-key",
    description="Saves the user's secret symmetric key to the server for future usage.\n\n" \
                "This is required for encryption and decryption of the user's data (client-side).",
    response_model=SaveKeyResponse,
    response_class=PrettyJSONResponse,
)
async def save_key(request: Request, data_payload: SaveKeyRequest):
    generate_nonce()
    validate_csrf_token(request, data_payload.csrf_token)
    key = USER_DATA.decrypt_user_payload(
        encrypted_data=read_user_data(data_payload.secret_key),
        digest_method=data_payload.server_digest_method
    )
    encrypted_key = AESGCM.symmetric_encrypt(
        plaintext=key,
        key_id=AC.DATABASE_KEY_ID
    )

    ip_address = get_user_ip(request)
    ip_address = hashlib.sha512(format_ip_address(ip_address)).hexdigest()
    key_id = base64.b85encode(secrets.token_bytes(64)).decode("utf-8")
    expiry_date = int(time.time()) + AC.KEYS_EXPIRY_TIME

    client, has_errors = get_mongodb_client(), False
    try:
        db = client[AC.DATABASE_NAME]
        await db[AC.KEYS_COLLECTION_NAME].insert_one({
            "_id": bson.ObjectId(),
            "key_id": key_id,
            "secret_key": bson.Binary(encrypted_key),
            "ip_address": ip_address,
            "expiry": datetime.utcfromtimestamp(expiry_date)
        })
    except (pymongo_errors.PyMongoError) as e:
        CLOUD_LOGGER.error(
            content={
                "message": "Failed to save user's secret key",
                "error": str(e)
            }
        )
        has_errors = True
    finally:
        client.close()

    if (has_errors):
        raise APIException(
            error="there is currently an issue with the database, please try again later.",
            status_code=500
        )

    signed_token = API_HMAC.sign(
        payload={"key_id": key_id},
        expiry_date=expiry_date
    )

    encrypted_token = USER_DATA.encrypt_user_payload(
        user_data=signed_token,
        user_public_key=data_payload.client_public_key,
        digest_method=data_payload.client_digest_method
    )
    return {"key_id_token": encrypted_token}

@api.post(
    path="/get-key",
    description="Retrieves the user's secret symmetric key from the server for encryption and " \
                "decryption of the user's data (client-side).",
    response_model=GetKeyResponse,
    response_class=PrettyJSONResponse,
)
async def get_key(request: Request, data_payload: GetKeyRequest):
    generate_nonce()
    validate_csrf_token(request, data_payload.csrf_token)
    key_id_token = USER_DATA.decrypt_user_payload(
        encrypted_data=read_user_data(data_payload.key_id_token),
        digest_method=data_payload.server_digest_method,
        decode=True
    )
    key_id_dict = API_HMAC.get(
        token=key_id_token,
        default={}
    )
    key_id = key_id_dict.get("key_id", None)
    if (key_id is None):
        raise APIException(
            error="key id token not found",
            status_code=404
        )

    ip_address = get_user_ip(request)
    ip_address = hashlib.sha512(format_ip_address(ip_address)).hexdigest()

    client, has_errors = get_mongodb_client(), False
    try:
        db = client[AC.DATABASE_NAME]
        key_info = await db[AC.KEYS_COLLECTION_NAME].find_one({
            "key_id": key_id,
            "ip_address": ip_address,
            "expiry": {"$gt": datetime.utcnow()}
        })
    except (pymongo_errors.PyMongoError) as e:
        CLOUD_LOGGER.error(
            content={
                "message": "Failed to retrieve user's secret key",
                "error": str(e)
            }
        )
        has_errors = True
    finally:
        client.close()

    if (has_errors):
        raise APIException(
            error="there is currently an issue with the database, please try again later.",
            status_code=500
        )

    if (key_info is None):
        raise APIException(
            error="key id token not found",
            status_code=404
        )

    key_info = AESGCM.symmetric_decrypt(
        ciphertext=key_info["secret_key"],
        key_id=AC.DATABASE_KEY_ID
    )
    encrypted_key = USER_DATA.encrypt_user_payload(
        user_data=key_info,
        user_public_key=data_payload.client_public_key,
        digest_method=data_payload.client_digest_method
    )
    return {"secret_key": encrypted_key}