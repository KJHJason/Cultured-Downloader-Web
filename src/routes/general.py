# import flask libraries (Third-party libraries)
from flask import render_template, Blueprint, redirect

# import Python's standard libraries
import pathlib

# import local python libraries
from functions import format_server_time

general = Blueprint("generalBP", __name__, static_folder="static", template_folder="template")

@general.route("/favicon.ico")
def favicon():
    """Return the favicon of the web app."""
    return redirect(location="https://api.cultureddownloader.com/favicon.ico", code=301)

@general.route("/")
def index():
    context = {"server_time": format_server_time()}
    return render_template("general/home.html", context=context)