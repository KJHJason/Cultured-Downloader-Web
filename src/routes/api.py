# import flask libraries (Third-party libraries)
from flask import request, Blueprint, jsonify, current_app

# import local python libraries
from functions import send_request
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

    return jsonify(send_request(queryID, gdriveType), 200)