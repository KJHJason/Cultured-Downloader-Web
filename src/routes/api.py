# import flask libraries (Third-party libraries)
from flask import request, Blueprint, jsonify, current_app

# import local python libraries
from functions import send_request, validate_schema
from classes import APP_CONSTANTS as AC, USER_COOKIE
from classes.exceptions import CRC32ChecksumError, DecryptionError
from .security import LIMITER

api = Blueprint("api", __name__, static_folder="static", template_folder="template")
LIMITER.limit(limit_value=current_app.config["APP_CONSTANTS"].API_REQUEST_LIMIT)(api)

@api.post("/api/v1/query")
def query():
    dataPayload = request.json.get("data")
    if (dataPayload is None):
        return jsonify({"error": "No data payload was provided."}), 400

    queryID = dataPayload.get("id")
    gdriveType = dataPayload.get("type")
    if (queryID is None or gdriveType is None):
        return jsonify({"error": "No ID or Google Drive type was provided."}), 400

    if (gdriveType != "file" and gdriveType != "folder"):
        return jsonify({"error": "Invalid type"}), 400

    return jsonify(send_request(queryID, gdriveType))

@api.get("/api/v1/rsa/public-key")
def get_rsa_public_key():
    return jsonify({"public_key": USER_COOKIE.get_api_public_key()})

@api.post("/api/v1/encrypt-cookie")
def encrypt():
    jsonPayload = request.json
    if (not validate_schema(schema=AC.USER_SENT_COOKIE_SCHEMA, data=jsonPayload)):
        return jsonify(
            {"error": "Invalid json format, please refer to the schema below and try again.",
            "schema": AC.USER_SENT_COOKIE_SCHEMA}
        ), 400

    cookiePayload = USER_COOKIE.decrypt_cookie_payload(jsonPayload["cookie"])
    if ("error" in cookiePayload):
        return jsonify(cookiePayload), 400

    try:
        encryptedCookieData = USER_COOKIE.encrypt_cookie_data(
            cookieData=cookiePayload["payload"],
            userPublicKey=jsonPayload["public_key"]
        )
    except (CRC32ChecksumError):
        return jsonify({"error": "Integrity checks failed."}), 400

    return jsonify({"cookie": encryptedCookieData})

@api.post("/api/v1/decrypt-cookie")
def decrypt():
    jsonPayload = request.json
    if (not validate_schema(schema=AC.USER_SENT_COOKIE_SCHEMA, data=jsonPayload)):
        return jsonify(
            {"error": "Invalid json format, please refer to the schema below and try again.",
            "schema": AC.USER_SENT_COOKIE_SCHEMA}
        ), 400

    encryptedCookiePayload = USER_COOKIE.decrypt_cookie_payload(jsonPayload["cookie"])
    if ("error" in encryptedCookiePayload):
        return jsonify(encryptedCookiePayload), 400

    print(encryptedCookiePayload)
    try:
        decryptedCookieData = USER_COOKIE.decrypt_cookie_data(
            encryptedCookieData=encryptedCookiePayload["payload"], 
            userPublicKey=jsonPayload["public_key"]
        )
    except (TypeError):
        return jsonify({"error": "Encrypted cookie must be in bytes."}), 400
    except (CRC32ChecksumError):
        return jsonify({"error": "Integrity checks failed, please try again."}), 400
    except (DecryptionError):
        return jsonify({"error": "Decryption failed."}), 400

    return jsonify({"cookie": decryptedCookieData})