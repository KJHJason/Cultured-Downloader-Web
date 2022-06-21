from flask import Flask, render_template, abort, request, make_response
from os import environ
import requests, time
import secrets

"""--------------------------- Start of Flask Configuration ---------------------------"""

app = Flask(__name__)

app.config["SECRET_KEY"] = secrets.token_bytes(128)

app.config["REQUESTS_HEADERS"] = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
    "referer": "https://cultureddownloader.com/query"
}

app.config["GOOGLE_API_KEY"] = "AIzaSyBch3wqIUlW5SDacOT7yAzeJRe2Jh4NsEA"

"""--------------------------- End of Flask Configuration ---------------------------"""

"""--------------------------- Start of Functions ---------------------------"""

def send_request(gdriveID, gdriveType):
    GOOGLE_API_KEY = app.config["GOOGLE_API_KEY"]
    return (
        requests.get(f"https://www.googleapis.com/drive/v3/files/{gdriveID}?key={GOOGLE_API_KEY}", headers=app.config["REQUESTS_HEADERS"]).json() 
        if gdriveType == "file" 
        else 
        requests.get(f"https://www.googleapis.com/drive/v3/files?q=%27{gdriveID}%27+in+parents&key={GOOGLE_API_KEY}", headers=app.config["REQUESTS_HEADERS"]).json()
        )

def format_server_time():
	serverTime = time.localtime()
	return time.strftime("%I:%M:%S %p", serverTime)

"""--------------------------- End of Functions ---------------------------"""

"""--------------------------- Start of App Routes ---------------------------"""

@app.route("/")
def index():
	context = { "server_time": format_server_time() }
	res = make_response(render_template("home.html", context=context))
	res.headers["Cache-Control"] = "public, max-age=300, s-maxage=600"
	return res

@app.route("/query", methods=["GET", "POST"])
def query():
	if request.method == "POST":
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
	else:
		abort(404)

"""--------------------------- End of App Routes ---------------------------"""

if __name__ == "__main__":
	app.run(debug=False, host="0.0.0.0", port=int(environ.get("PORT", 8080)))