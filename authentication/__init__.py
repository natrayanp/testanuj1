from flask import Blueprint

bp_auth = Blueprint('auth', __name__)    # oauth login routes
bp_login = Blueprint('login', __name__)  # front end login routes
