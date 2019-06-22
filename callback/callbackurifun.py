from . import bp_accallbk
from flask import redirect, request,make_response, jsonify
#from flask_cors import CORS, cross_origin
from assetscube.common import dbfunc as db
from assetscube.common import error_logics as errhand
from assetscube.common import jwtfuncs as jwtf
from assetscube.common import settings as settings
from datetime import datetime
import pkgutil
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
import json
import requests
import jwt

@bp_accallbk.route("/callback",methods=["GET","POST","OPTIONS"])
def callback():
    if request.method=="OPTIONS":
            print("inside callback options")
            response = "inside callback options"
            #print(request.headers)
            response1 = make_response(jsonify(response))            
            return response1

    elif request.method=="GET":
        print("inside callback get")
        params = request.args
        print(params)
        print(settings.MYNOTIPG[settings.LIVE])
 
        response1 = make_response(redirect(settings.MYNOTIPG[settings.LIVE]+"?type="+typ+"&regdata="+regdata+"&msg="+msg, code=302))

        response1.headers['Access-Control-Allow-Origin'] = "*"
        response1.headers['Access-Control-Allow-Methods'] = "GET, POST, PATCH, PUT, DELETE, OPTIONS"
        response1.headers['Access-Control-Allow-Headers'] = "Origin, entityid, Content-Type, X-Auth-Token, countryid"
        print(response1.headers)
        return response1

    elif request.method=="POST":
        print("inside callback POST")
        payload = request.get_json()
        print("payload 11111111")
        print(payload)
       
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        response1 = make_response(redirect(settings.MYNOTIPG[settings.LIVE]+"?type="+typ+"&regdata="+regdata+"&msg="+msg, code=302))

        return resps    