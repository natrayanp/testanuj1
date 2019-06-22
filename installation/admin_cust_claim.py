from . import bp_install

from flask import redirect, request,make_response, jsonify

from assetscube.common import dbfunc as db
from assetscube.common import error_logics as errhand
from assetscube.common import jwtfuncs as jwtf
from assetscube.common import serviceAccountKey as sak
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
import os
import hashlib
import hmac
import binascii
import jwt
import string
import random
import json

'''
import requests
import json
payload = {"email": "admin@gmail.com", "entityid": "NAWALCUBE", "countryid": "IN"}
url = "http://127.0.0.1:8080/admincustclaim"
r = requests.post(url, data=json.dumps(payload))
print(r.status_code)
print(r.text)
'''

@bp_install.route("/admincustclaim",methods=["GET","POST","OPTIONS"])
def admincustclaim():
    if request.method=="OPTIONS":
        print("inside admincustclaim options")
        response1 = make_response(jsonify("inside admincustclaim options"))
        return response1

    elif request.method=="POST":
        print("inside admincustclaim POST")
        #payload = request.get_json()
        daa = request.data
        payload = json.loads(daa)
        print("payload")
        print(payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        s = 0
        f = None
        t = None #message to front end
        uid = None

        email = payload["email"]
        entityid = payload["entityid"]
        countryid = payload["countryid"]
        usercusttype = "A"

        try:
            print('inside try')
            default_app = firebase_admin.get_app('natfbappsingup')
            print('about inside try')
        except ValueError:
            print('inside value error')
            #cred = credentials.Certificate(os.path.dirname(__file__)+'/serviceAccountKey.json')
            cred = credentials.Certificate(sak.SERVICEAC)
            default_app = firebase_admin.initialize_app(credential=cred,name='natfbappsingup')
        else:
            pass

            print('app ready')        
            email = payload["email"]            
        try:
            user = auth.get_user_by_email(email,app=default_app)
        except AuthError:
            print('AuthError')
            print(AuthError)            
            s, f, t = errhand.get_status(s, 100, f, "email id " + email + " not registered", t, "yes")            
        else:
            s, f, t = errhand.get_status(s, 0, f, "User id already exists", t, "no")
            uid = format(user.uid)
            print(uid)
        if uid != None or uid != '':
            try:
                print('start set custom')
                auth.set_custom_user_claims(uid, {"entityid": entityid, "countryid": countryid, "custtype": usercusttype},app=default_app)
                print('end set custom')
            except ValueError:
                print('valuererror')
                s, f, t = errhand.get_status(s, 100, f, "Not a valid user properties", t, "yes")
            except AuthError:
                print('AuthError')
                s, f, t = errhand.get_status(s, 100, f, "Not a valid user credentials", t, "yes")

        if s <= 0:
            return make_response(jsonify("success"), 200)
        else:
            return make_response(jsonify(errhand.front_end_msg), 400)