# import third-party libraries
import bson
import pymongo.errors as pymongo_errors
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

# import local python libraries
from functions import   get_user_ip, generate_csrf_token, validate_csrf_token, \
                        get_mongodb_client, format_ip_address, read_user_data
from classes import APP_CONSTANTS as AC, CLOUD_LOGGER, AESGCM, USER_DATA, API_JWT_HMAC
from classes.exceptions import APIException
from classes.responses import PrettyJSONResponse
from classes.middleware import generate_nonce, exempt_csp
from classes.v1 import  CsrfResponse, SaveKeyRequest, SaveKeyResponse, \
                        PublicKeyResponse, PublicKeyRequest, GetKeyRequest, GetKeyResponse

# import Python's standard libraries
import time
import hashlib
import secrets
import base64
from datetime import datetime

api = FastAPI(
    debug=AC.DEBUG_MODE,
    title="Cultured Downloader API",
    description="""An API by <a href='https://github.com/KJHJason'>KJHJason</a> to help users like you 
with batch downloading content safely from Pixiv Fanbox and Fantia.\n
You would not want someone else to get a hold of your saved cookies and GDrive API key, right?\n
Even after encrypting the data, the secret key must be stored somewhere, and that's where this API comes in.\n
This API is for storing the user's secret key securely in the server's database for future use.\n
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

@api.get(
    path="/csrf-token",
    description="Returns a CSRF token for the user to use in a request, if required.",
    response_model=CsrfResponse,
    response_class=PrettyJSONResponse,
)
async def get_csrf_token(request: Request, response: Response):
    generate_nonce()
    return {"csrf_token": generate_csrf_token(request=request, response=response)}

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

    CLOUD_LOGGER.info(
        content=f"User {get_user_ip(request)}: Saving their symmetric key"
    )
    key = USER_DATA.decrypt_user_payload(
        encrypted_data=read_user_data(data_payload.secret_key),
        digest_method=data_payload.server_digest_method
    )

    # Check if the secret key is valid
    if (len(key) != 32):
        raise APIException(
            error="your secret key must be 256 bits (32 bytes) long",
        )
    try:
        key.decode("utf-8")
    except (UnicodeDecodeError):
        pass
    else:
        raise APIException(
            error="your secret key is invalid, please generate another secret key again using a secure pseudo-random number generator",
        )

    encrypted_key = AESGCM.symmetric_encrypt(
        plaintext=key,
        key_id=AC.DATABASE_KEY_ID
    )

    ip_address = get_user_ip(request)
    hashed_ip_address = hashlib.sha512(format_ip_address(ip_address)).hexdigest()
    key_id = base64.b85encode(secrets.token_bytes(64)).decode("utf-8")
    expiry_date = int(time.time()) + AC.KEYS_EXPIRY_TIME

    client, has_errors = get_mongodb_client(), False
    try:
        collection = client[AC.DATABASE_NAME][AC.KEYS_COLLECTION_NAME]
        no_of_keys = await collection.count_documents({"ip_address": hashed_ip_address})
        if (no_of_keys >= AC.MAX_KEYS_PER_IP):
            # If the user has more than the maximum 
            # number of keys, delete the oldest key.
            matched_documents = collection.find({"ip_address": hashed_ip_address})
            keys_arr = await matched_documents.to_list(length=AC.MAX_KEYS_PER_IP)
            await collection.delete_one({"expiry": min(keys_arr, key=lambda doc: doc["expiry"])})

        await collection.insert_one({
            "_id": bson.ObjectId(),
            "key_id": key_id,
            "secret_key": bson.Binary(encrypted_key),
            "ip_address": hashed_ip_address,
            "expiry": datetime.utcfromtimestamp(expiry_date)
        })
    except (pymongo_errors.PyMongoError) as e:
        CLOUD_LOGGER.error(
            content={
                "message": "Failed to save user's secret key",
                "error": str(e),
                "ip_address": ip_address
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

    signed_token = API_JWT_HMAC.sign(
        payload={"key_id": key_id},
        expiry_date=expiry_date
    )
    encrypted_token = USER_DATA.encrypt_user_payload(
        user_data=signed_token,
        user_public_key=data_payload.client_public_key,
        digest_method=data_payload.client_digest_method
    )
    CLOUD_LOGGER.info(
        content=f"User {get_user_ip(request)}: Saved their symmetric key [key_id: {key_id}]"
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

    CLOUD_LOGGER.info(
        content={
            "message": f"User {get_user_ip(request)}: Retrieving their symmetric key",
            "key_id_token": data_payload.key_id_token
        }
    )
    key_id_token = USER_DATA.decrypt_user_payload(
        encrypted_data=read_user_data(data_payload.key_id_token),
        digest_method=data_payload.server_digest_method,
        decode=True
    )
    key_id_dict = API_JWT_HMAC.get(
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
    hashed_ip_address = hashlib.sha512(format_ip_address(ip_address)).hexdigest()

    client, has_errors = get_mongodb_client(), False
    try:
        db = client[AC.DATABASE_NAME]
        key_info = await db[AC.KEYS_COLLECTION_NAME].find_one({
            "key_id": key_id,
            "ip_address": hashed_ip_address,
            "expiry": {"$gt": datetime.utcnow()}
        })
    except (pymongo_errors.PyMongoError) as e:
        CLOUD_LOGGER.error(
            content={
                "message": "Failed to retrieve user's secret key",
                "error": str(e),
                "ip_address": ip_address
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
    CLOUD_LOGGER.info(
        content=f"User {get_user_ip(request)}: Retrieved their symmetric key [key_id: {key_id}]"
    )
    return {"secret_key": encrypted_key}