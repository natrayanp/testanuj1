from . import bp_auth, bp_login

from flask import redirect, request,make_response, jsonify

from assetscube.common import dbfunc as db
from assetscube.common import error_logics as errhand
from assetscube.common import jwtfuncs as jwtf
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

@bp_auth.route('/appname',methods=["POST","OPTIONS"])
def appname():
    # Return app name
    if request.method=="OPTIONS":
        print("inside appname options")
        return "inside appname options"

    elif request.method=="POST":
        print("inside appname POST")
        payload = request.get_json()
        print(payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        #userid = jwtf.decodetoken(request, needtkn = False)
        entityid = request.headers.get("entityid", None)
        cntryid = request.headers.get("countryid", None)
        
        criteria_json = {
            # "userid"   : userid,
            "entityid" : entityid,
            "cntryid"  : cntryid,
            "payload" : payload
        }
        
        res_to_send, response = fn_appname(criteria_json)

        if res_to_send == "success":
            response1 = response
            resps = make_response(jsonify(response1), 200)
        else:
            response1 = {"errormessage": response["usrmsg"]}
            resps = make_response(jsonify(response1), 403)

        print(resps)
        print("returning app name")
        return resps

def fn_appname(criteria_json):
    print("inside fn_appname function")
    s = 0
    f = None
    t = None #message to front end
    response = None
    res_to_send = 'fail'
    payload = criteria_json.get("payload",None)
    
    print(s)
    if s <= 0:
        if criteria_json.get("entityid", None) != None:
            entityid = criteria_json['entityid']
        else:
            entityid = None
            s, f, t= errhand.get_status(s, 100, f, "entity id not provided", t, "yes")

        if criteria_json.get("cntryid", None) != None:
            cntryid = criteria_json['cntryid']
        else:
            cntryid = None
            s, f, t= errhand.get_status(s, 100, f, "cntry code is not provided", t, "yes")       
        
        if payload == None:
            s, f, t= errhand.get_status(s, 100, f, "App data not sent.  Please try again", t, "yes")
        else:
            if payload.get("appid", None) != None:
                appid = payload['appid']
            else:
                appid = None
                s, f, t= errhand.get_status(s, 100, f, "app id not provided", t, "yes")

            if payload.get("redirecturi", None) != None:
                redirecturi = payload['redirecturi']
            else:
                redirecturi = None
                s, f, t= errhand.get_status(s, 100, f, "redirecturi is not provided", t, "yes")
                # update or create are the values
    
    print(appid,redirecturi,entityid,cntryid)

    if s <= 0:
        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print("DB connection established", s,f,t)
    

    if s <= 0:
        command = cur.mogrify("""
                                SELECT json_agg(a) FROM (
                                SELECT *
                                FROM ncapp.appdetail
                                WHERE delflg != 'Y' AND expirydate >= CURRENT_DATE AND approved != 'N'
                                AND appid = %s AND redirecturi = %s
                                AND entityid = %s AND countryid = %s
                                ) as a
                            """,(appid, redirecturi, entityid, cntryid,) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "App Name data fetch failed with DB error", t, "no")
    print(s,f)
    
    db_rec = None
    if s <= 0:
        db_rec = cur.fetchall()[0][0]
        print(db_rec)    
        
        if db_rec == None or len(db_rec) > 1:
            s, f, t= errhand.get_status(s, 100, f, "Unable to locate the app id", t, "yes")            
        else:
            db_rec = db_rec[0]
            print("auth.py line 136 App id identified successfully")
            pass            
    
    print(s,f)        
    if s > 0:
        res_to_send = 'fail'
        result_date = []
        response = {
            'result_data' : result_date,
            'status': res_to_send,
            'status_code': s,
            'usrmsg': errhand.error_msg_reporting(s, t)
            }
    else:
        res_to_send = 'success'
        result_data = { 
                            "appname": db_rec["appname"]
                      }
        response = {
                    'result_data' : result_data,
                    'status': res_to_send,
                    'status_code': 0,
                    'usrmsg': "Token generation successful"
        }

    print(res_to_send, response)
    
    return (res_to_send, response)



@bp_auth.route("/userauth",methods=["GET","POST","OPTIONS"])
def userauth():
    # This function is called to authenticate user for an app
    # Input --> 2
    #       1) in payload apiid, userid & redirecturi are mandatory
    #       2) in header countryid and entityid
    # Output --> 2
    #       1) success : auth tkn will be sent {'authtkn': auth token} 
    #       2) error: {"errormessage": response["usrmsg"]}
    if request.method=="OPTIONS":
        print("inside userauth options")
        return "inside userauth options"

    elif request.method=="POST":
        print("inside userauth POST")
        payload = request.get_json()
        print(payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        #userid = jwtf.decodetoken(request, needtkn = False)
        entityid = request.headers.get("entityid", None)
        cntryid = request.headers.get("countryid", None)
        
        criteria_json = {
            # "userid"   : userid,
            "entityid" : entityid,
            "cntryid"  : cntryid,
            "payload" : payload
        }
        print("cal @@@@@@@@@@@@@@@@")
        res_to_send, response = app_userauth(criteria_json)
        print("back @@@@@@@@@@@@@@@@@@@@@@@")
        print(res_to_send, response)
        if res_to_send == "success":
            #response1 = response["result_data"]
            response1 = make_response(jsonify(response["result_data"]))
            response1.headers['Access-Control-Allow-Origin'] = "*"
            response1.headers['Access-Control-Allow-Methods'] = "GET, POST, PATCH, PUT, DELETE, OPTIONS"
            response1.headers['Access-Control-Allow-Headers'] = "Origin, entityid, Content-Type, X-Auth-Token, countryid"
            resps = response1
            print("nat")
            print(resps)
            #resps = make_response(jsonify(response1), 200)
        else:
            response1 = {"error": response["usrmsg"]}
            resps = make_response(jsonify(response1), 403)

        return resps

def app_userauth(criteria_json):
    # Generate a user auth token
    # input 
    #   criteria_json = {
    #        "entityid" : entityid,
    #        "cntryid"  : cntryid,
    #        "payload" : payload  => {appid,redirecturi,userid,expiremin<tokenexipry in mins>}
    #   }
    # Output
    #    response = {
    #                'result_data' : result_data, => succ-> {'authtkn': auth_tkn} : err->[]
    #                'status': res_to_send, => success/fail
    #                'status_code': 0, 
    #                'usrmsg': "Token generation successful" <=for success:  error msg in case of error
    #    }
    
    
    print("inside userauth function")
    s = 0
    f = None
    t = None #message to front end
    response = None
    res_to_send = 'fail'
    payload = criteria_json.get("payload",None)
    
    print(s)
    if s <= 0:
        if criteria_json.get("entityid", None) != None:
            entityid = criteria_json['entityid']
        else:
            entityid = None
            s, f, t= errhand.get_status(s, 100, f, "entity id not provided", t, "yes")

        if criteria_json.get("cntryid", None) != None:
            cntryid = criteria_json['cntryid']
        else:
            cntryid = None
            s, f, t= errhand.get_status(s, 100, f, "cntry code is not provided", t, "yes")       
        
        if payload == None:
            s, f, t= errhand.get_status(s, 100, f, "App data not sent.  Please try again", t, "yes")
        else:
            if payload.get("appid", None) != None:
                appid = payload['appid']
            else:
                appid = None
                s, f, t= errhand.get_status(s, 100, f, "app id not provided", t, "yes")

            if payload.get("redirecturi", None) != None:
                redirecturi = payload['redirecturi']
            else:
                redirecturi = None
                s, f, t= errhand.get_status(s, 100, f, "redirecturi is not provided", t, "yes")

            if payload.get("userid", None) != None:
                userid = payload['userid']
            else:
                userid = None
                s, f, t= errhand.get_status(s, 100, f, "userid is not provided", t, "yes")

            expiremin = payload.get("expiremin", None)

    print(appid,redirecturi,entityid,cntryid,userid)

    if s <= 0:
        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print("DB connection established", s,f,t)
    

    if s <= 0:
        command = cur.mogrify("""
                                SELECT json_agg(a) FROM (
                                SELECT *
                                FROM ncapp.appdetail
                                WHERE delflg != 'Y' AND expirydate >= CURRENT_DATE AND approved != 'N'
                                AND appid = %s AND redirecturi = %s
                                AND entityid = %s AND countryid = %s
                                ) as a
                            """,(appid, redirecturi, entityid, cntryid,) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "App Name data fetch failed with DB error", t, "no")
    print(s,f)
    
    app_db_rec = None
    if s <= 0:
        app_db_rec = cur.fetchall()[0][0]
        print(app_db_rec)
        if app_db_rec != None:
            print(len(app_db_rec))
    
        if app_db_rec == None or len(app_db_rec) < 1:
            s, f, t= errhand.get_status(s, 100, f, "Unable to locate the app id", t, "yes")            
        else:
            app_db_rec = app_db_rec[0]
            print("auth.py line 319 App id identified successfully")
            pass            
    
    print(s,f)

    #appuserid = app_db_rec.get("appuserid", None)
    if s <= 0:
        command = cur.mogrify("""
                            SELECT json_agg(a) FROM (
                            SELECT *
                            FROM ncusr.userlogin
                            WHERE userid = %s
                            AND entityid = %s AND countryid = %s
                            ) as a
                        """,(userid, entityid, cntryid,) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "User fetch failed with DB error", t, "no")
    print(s,f)

    usr_db_rec = None
    if s <= 0:
        usr_db_rec = cur.fetchall()[0][0]
        print(usr_db_rec)

        if usr_db_rec == None or len(usr_db_rec) < 1:
            s, f, t= errhand.get_status(s, 100, f, "Unable to locate the user details", t, "yes")            
        else:
            usr_db_rec = usr_db_rec[0]
            print("User details fetch successfull")
            pass            
    
    if s <= 0:
        if usr_db_rec["userstatus"] == 'B':
            #B-Blocked , I-Deleteduser
            s, f, t= errhand.get_status(s, 100, f, "User is blocked", t, "yes")
        elif usr_db_rec["userstatus"] == 'I':
            #B-Blocked , I-Deleteduser
            s, f, t= errhand.get_status(s, 100, f, "User is Deleted", t, "yes")

    #We are ready to generate API pass token
    print(s,f)

    if s <= 0:
        i = 0
        cur_time = datetime.now().strftime('%Y%m%d%H%M%S')
        authtknset = False
        auth_tkn = None

        while i < 50:
            r = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(6))
            auth_tkn = create_signature("md5", "nirunidhausrtkn" + r, userid + cur_time, appid + cur_time)

            command = cur.mogrify("""
                                    SELECT count(1)
                                    FROM ncusr.userauth
                                    WHERE userauthtkn = %s
                                """,(auth_tkn,) )
            print(command)
            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None
            print('----------------')
            print(s)
            print(f)
            print('----------------')
            if s > 0:
                s, f, t = errhand.get_status(s, 200, f, "auth token data fetch failed with DB error", t, "no")
            print(s,f)

            if s <= 0:
                db_rec = cur.fetchall()[0][0]
                print(db_rec)
            
                if db_rec > 0:
                    s, f, t= errhand.get_status(s, 100, f, "auth token Already exists. Retrying time: " + i, t, "no")
                    i = i + 1
                    continue
                else:
                    print("Auth token is unique.  Generation task completed")
                    authtknset = True
                    break
            else:
                # Some error occured, so no point looping
                authtknset = False
                break
    
    print(s,f, t)


    appusrtype = None if app_db_rec == None else app_db_rec.get("appusertype", None)

    if appusrtype == None:
        s, f, t= errhand.get_status(s, 200, f, "app user type is not known", t, "yes")

    if s <= 0 and authtknset:
        s1, f1 = db.mydbbegin(con, cur)
        print(s1,f1)

        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None


        if s <= 0:
            passexpiry = get_expiry_time("authtkn", appusrtype, expiremin)
            # VALUES(%s, %s, %s, %(timestamp)s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            command = cur.mogrify("""
                        INSERT into ncusr.userauth (userid,appid,userauthtkn,tknexpiry,entityid,countryid,octime,lmtime)
                        VALUES(%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        ON CONFLICT ON CONSTRAINT unq_comb_uauth
                        DO
                            UPDATE SET userauthtkn = %s, tknexpiry = %s, lmtime = CURRENT_TIMESTAMP 
                        """,(userid, appid, auth_tkn, passexpiry, entityid, cntryid, auth_tkn, passexpiry,))
            print(command)

            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s > 0:
                s, f, t= errhand.get_status(s, 200, f, "authtoken update failed", t, "no")

            print('Insert or update is successful')
    
        if s <= 0:
            con.commit()
   
    if s > 0:
        res_to_send = 'fail'
        result_data = []
        response = {
            'result_data' : result_data,
            'status': res_to_send,
            'status_code': s,
            'usrmsg': errhand.error_msg_reporting(s, t)
            }
    else:
        res_to_send = 'success'
        result_data = {'authtkn': auth_tkn}
        response = {
                    'result_data' : result_data,
                    'status': res_to_send,
                    'status_code': 0,
                    'usrmsg': "Token generation successful"
        }

    print(res_to_send, response)
    
    return (res_to_send, response)


def create_signature(hastype, more_key_str, key, message):
  d = more_key_str + key
  b = d.encode()

  message = message.encode()
  if hastype == "md5":
    return hmac.new(b, message, hashlib.md5).hexdigest()
  elif hastype == "sha256":
    return hmac.new(b, message, hashlib.sha256).hexdigest()


def get_expiry_time(tkn_type, ut, expiremin=None) -> datetime:
    print(tkn_type, ut)
    et = None
    if expiremin != None:
        et = datetime.now() + timedelta(min= expiremin)
    else:
        if tkn_type == "authtkn":
            # Set the app token expiry based on the user type
            # I - Investor - 1 day
            # D - MFD  - 1 hour
            # A - RIA  - 1 hour
            # P - Portfolio tool - 1 hour
            # T - Trusted app - 1 hour
            if ut == 'I':
                et = datetime.now() + timedelta(hours=1)
            elif ut == 'D':
                et = datetime.now() + timedelta(hours=1)
            elif ut == 'A':
                et = datetime.now() + timedelta(hours=1)
            elif ut == 'P':
                et = datetime.now() + timedelta(hours=1)
            elif ut == 'T':
                reference_time = datetime.now()
                print(reference_time)
                et = reference_time.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1,microseconds=-1)       
                print(et)
                #Example et value 2018-09-04 23:59:59.999999
        elif tkn_type == "passtkn":
            # Set the user token expiry based on the user type
            # I - Investor - 1 day
            # D - MFD  - no Expiry
            # A - RIA  - no Expiry
            # P - Portfolio tool - 1 day
            # T - Trusted app - no Expiry
            if ut == 'I':
                reference_time = datetime.now()
                et = reference_time.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1,microseconds=-1) 
            elif ut == 'D':
                et = datetime.now() + timedelta(years=100)
            elif ut == 'A':
                et = datetime.now() + timedelta(years=100)
            elif ut == 'P':
                reference_time = datetime.now()
                et = reference_time.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1,microseconds=-1) 
            elif ut == 'T':            
                et = datetime.now() + timedelta(years=100)
    print(et)
    return et
    #return et.strftime('%d-%m-%YT%H:%M:%S')