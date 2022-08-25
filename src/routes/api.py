# import flask libraries (Third-party libraries)
from flask import request, abort, Blueprint, make_response

# import local python libraries
from functions import send_request

api = Blueprint("api", __name__, static_folder="static", template_folder="template")

@api.post("/query")
def query():
    reqData = ""
    dataPayload = request.json.get("data")
    queryID = dataPayload.get("id")
    gdriveType = dataPayload.get("type")
    if gdriveType == "file":
        reqData = send_request(queryID, gdriveType)
    elif gdriveType == "folder":
        reqData = send_request(queryID, gdriveType)
    else:
        abort(404)
    return make_response(reqData, 200)