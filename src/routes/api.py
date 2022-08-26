# import flask libraries (Third-party libraries)
from flask import request, Blueprint, jsonify, current_app

# import local python libraries
from functions import send_request
from classes import AESGCM, APP_CONSTANTS as AC, RSA4096
from classes.exceptions import CRC32ChecksumError, DecryptionError
from .security import LIMITER

api = Blueprint("api", __name__, static_folder="static", template_folder="template")
LIMITER.limit(limit_value=current_app.config["APP_CONSTANTS"].API_REQUEST_LIMIT)(api)

@api.post("/query")
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

@api.route("/rsa/public-key")
def get_rsa_public_key():
    return jsonify({"public_key": RSA4096.get_public_key(keyID=AC.RSA_KEY_ID, getStr=True)})

@api.post("/encrypt-cookie")
def encrypt():
    cookieData = request.json.get("cookie")
    if (cookieData is None):
        return jsonify({"error": "No cookie data was provided."}), 400

    try:
        encryptedCookieData = AESGCM.encrypt(cookieData, keyID=AC.COOKIE_ENCRYPTION_KEY)
    except (CRC32ChecksumError):
        return jsonify({"error": "Integrity checks failed."}), 400
    else:
        return jsonify({"cookie": encryptedCookieData})

@api.post("/decrypt-cookie")
def decrypt():
    cookieData = request.json.get("cookie")
    if (cookieData is None):
        return jsonify({"error": "No cookie data was provided."}), 400

    try:
        decryptedCookieData = AESGCM.decrypt(cookieData, keyID=AC.COOKIE_ENCRYPTION_KEY)
    except (TypeError):
        return jsonify({"error": "Encrypted cookie must be in bytes."}), 400
    except (CRC32ChecksumError):
        return jsonify({"error": "Integrity checks failed, please try again."}), 400
    except (DecryptionError):
        return jsonify({"error": "Decryption failed."}), 400
    else:
        return jsonify({"cookie": decryptedCookieData})