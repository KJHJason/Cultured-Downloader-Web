from flask import Flask, render_template, abort, request, make_response
from os import environ
import requests, time

"""--------------------------- Start of Flask Configuration ---------------------------"""

app = Flask(__name__)

app.config["SECRET_KEY"] = "seUR2EvLfZ#2GGQf63E%?qVuavvKS2YwH=pUJH$jB*eLxg*$wfCJS&UnvQ$m%3*L%GNqGMScTZNNj!?f35^vUe72uuPZTC-y3%9+maUEW#TKTZ@+5#Dm?S5hU8PmxusrJ249szv4zdU-s%w*D=5ZH9qwHDP%fBDAH!-Tu9nEdq*8_^?G=8LXURC+G=+Yn#y4uQBKD$mJmNzuqu2SxbNbS*D3L!b#yFA_!zfn4L22rLhf4puS=+W=tQA_H7n#PufX9Em&nXn^Lt9m*da^Mv?9qHx?J86P=EPcAc#6#A3&vb8j42b3XZftU&n_2%jHvx#sLzKZ8nT!NTQA#8m_JT3ucer?6!b-U+6ZsnneqEAX_X!ve6qH=wd9+?XDrE9zKEJ3^6SPJ+uDnLAgVaG_aX#E8gKt5#2ZzPQyw66u8^62SUs6v@qwyRXGKpAKg!bu@6T$$DSM$=5!&Y-F2hvE=B2fzay#7Pv@hcCKx#x64kYxekbHdycaM&9zMhMx7syeH^k*UPydwPkdBf8QScX2FTcgCLPVMxPV+89DeBwQjPe2@N%ZY4f@?RrM$#SPwbWD8RycuJ7AFKE9s!ZH3#R_r2naETF!4!X4?t4NffR46QBzRuYret#DXgqfu$XUmcBCyhgMYa%fu8!!QFXhr4H-eL+q_8TnCRr&x_h@HeQrCFKAf+bEG#HYpFXL#=yDVhQ2-U?kS??C-a&$D3_mG6JdVaL2VKhmDzAbuAaKFXr*^?&uaUYvPLk6AtfswLp?y!LRYGSyALuv4u_49-S2tBDtm8ryEWm&jMkm#tM6#^m+6*jzh7sKmZ4zLmGDJrZwM^WMvNWkm#NN*XvvV*eS8be*tV$$VZBXK?SNCB^r7z2*?V%mGW2%Qu@^E$ZD#S9mQL!Exf2mzm9AHD$HcuLtaEA%n9pu*DeBu+Kv5!&s#V^26Y%Cd79yuh7rS=$mQMSXeU&44q_m8ZXB2Y%wUf2kPJELfP!hxJwZHvUA!7Sjuh@S%*dG?qt@Lm5rRSNMaC+Q!w8F*DvkmGdx&YTA$Umydp$AFA=qRpe*#mhR8p%Y$vXf!LV8nsS2Z+*bS$$mDcRXBT^B%5Eka+yt2WvsrMz3SZAry#B9DB++krHA@C5FpbVZf@D-n2CWkNJAUY2CjYQ_rc+t^+Lv=y_G?#Wm+pQsb8m=CFbGZ!Z#=w2^DDj3Bu?4&XT@YFtXWx_$&sMdsUs7ZzG3L4@9TbXTn-8g*GCgWUQ7CYBrtXCEvc^??Sg2habN*hRH=nFQe!&M3U-SBhBX9$=4YgDL=BXkFT#&$b#Ew9nhBewLsmdXG9fpB?rA9Mf@k-vL4L@^D5@@54McT4FdCB$TYBQWn!QFUZrZ!_rDU@9#qG*bF-hzK@!H#x8b%_eF?Kqph-U6y7UV^K*W*EQx2@L3H%xkDc$Xu=YFB*+w-9$@m#m4C^C7VY+jHWXmgb2aGpPX!d7w9E=gw%jzWJ?sV85Fqhf69zBd@L3TZj&LtQ^qSQ85cSkupMSnNcHg&qwP7Ap%WuJg$d-zZJW5huz6BGsjv=buQvP&Trf#Wam9255xm#EaD6J9#!g2*bL*-m%S3zBujrK-#d=Z+!@bzmcnyW-TPVm&qtUn=^vkgKr=fAP-&62#-yG2M!=?u!cC+muAL#FSP*WdFKhEsRqwu&MsE5+q4z+5hSEpWZ9htu4F*8T-9fmy9_7w^&Z+hvn3u4x5zBdMY@Ks?wVVw^k#LPMePN&*6urCTsqCtd6Ka6DRx66a-zDG$tEjzcMr6fpFGzHMhhE7GRy@DASkKA6LnQh6YTLEXfq^Z_wG2JfSHvXGVE5!fHZpvGFFqkDB7!PrMJ-h6SpCb+r4=eHLB&ndXf_%fGfkLbzh2%u3n4cHqcppj=9b*4mp%%p8?2P5DX25dh_y7hGP!379ASFHfR&!=BV%3SgVzz2$WLc#Ka7zjD9*LPmXVGN-?NbT$k?S*@Qdg4nKEFT75Np34ke&R!jVeT7?CpHeb-VSshEvNjb?#CTC4!aKu+Ja_fqVW-dN4BkxAKZAjz4_FJwRA9Zd!NL&JFWMH_uCV%8Z"

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