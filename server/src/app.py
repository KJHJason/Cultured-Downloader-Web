from flask import Flask, render_template, abort, request, make_response
from os import environ
import requests, time

app = Flask(__name__)

DEBUG_MODE = False

GOOGLE_API_KEY = "AIzaSyBch3wqIUlW5SDacOT7yAzeJRe2Jh4NsEA"

def format_server_time():
	serverTime = time.localtime()
	return time.strftime("%I:%M:%S %p", serverTime)

@app.route("/")
def index():
	context = { "server_time": format_server_time() }
	return render_template("home.html", context=context)

@app.route("/query", methods=["GET", "POST"])
def query():
	if request.method == "POST":
		reqData = ""
		dataPayload = request.json.get("data")
		queryID = dataPayload.get("id")
		gdriveType = dataPayload.get("type")
		if gdriveType == "file":
			req = requests.get(f"https://www.googleapis.com/drive/v3/files/{queryID}?key={GOOGLE_API_KEY}")
			reqData = req.json()
		elif gdriveType == "folder":
			req = requests.get(f"https://www.googleapis.com/drive/v3/files?q=%27{queryID}%27+in+parents&key={GOOGLE_API_KEY}")
			reqData = req.json()
		else:
			abort(404)
		return make_response(reqData, 200)
	else:
		abort(404)

if __name__ == "__main__":
	app.run(debug=DEBUG_MODE, host="0.0.0.0", port=int(environ.get("PORT", 8080)))