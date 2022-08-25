# import flask libraries (Third-party libraries)
from flask import render_template, Blueprint, make_response

# import local python libraries
from functions import format_server_time

general = Blueprint("generalBP", __name__, static_folder="static", template_folder="template")

@general.route("/")
def index():
    context = {"server_time": format_server_time()}
    res = make_response(render_template("home.html", context=context))
    res.headers["Cache-Control"] = "public, max-age=300, s-maxage=600"
    return res