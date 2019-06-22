from flask import Flask
from flask import request
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app,supports_credentials=True,headers='Content-Type,countryid')

from assetscube import authentication


#app.config.from_object('settings')

from assetscube.flows import bp_flow
from assetscube.flows import flow
from assetscube.authentication import bp_auth, bp_login
from assetscube.authentication import auth
from assetscube.authentication import login
from assetscube.appfunc import appfuncs, appauth, bp_appfunc
from assetscube.installation import bp_install, admin_cust_claim

app.register_blueprint(bp_flow)
app.register_blueprint(bp_auth)
app.register_blueprint(bp_login)
app.register_blueprint(bp_appfunc)
app.register_blueprint(bp_install)