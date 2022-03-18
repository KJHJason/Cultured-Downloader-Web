from flask import Flask, render_template, abort, request, make_response
import requests, time, os

app = Flask(__name__)

GOOGLE_API_KEY = "AIzaSyBch3wqIUlW5SDacOT7yAzeJRe2Jh4NsEA"

def format_server_time():
	server_time = time.localtime()
	return time.strftime("%I:%M:%S %p", server_time)

@app.route("/")
def index():
	context = { "server_time": format_server_time() }
	return render_template("home.html", context=context)

@app.post("/query")
def query():
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
		abort(403)
	return make_response(reqData, 200)

if __name__ == "__main__":
	app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))