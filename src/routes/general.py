# import flask libraries (Third-party libraries)
from flask import render_template, Blueprint, make_response, send_from_directory, current_app

# import Python's standard libraries
import pathlib

# import local python libraries
from functions import format_server_time

general = Blueprint("generalBP", __name__, static_folder="static", template_folder="template")

@general.route("/favicon.ico")
def favicon() -> make_response:
    """Return the favicon of the web app."""
    return send_from_directory(
        directory=pathlib.Path(current_app.root_path).joinpath("static", "images", "icons"),
        path="favicon.ico",
        mimetype="image/vnd.microsoft.icon"
    )

@general.route("/")
def index():
    context = {"server_time": format_server_time()}
    return render_template("general/home.html", context=context)