from . import bp_appfunc
from flask import redirect,request,make_response, jsonify
#from flask_cors import CORS, cross_origin
from assetscube.common import dbfunc as db
from assetscube.common import error_logics as errhand
from assetscube.common import jwtfuncs as jwtf
from assetscube.common import serviceAccountKey as sak
from assetscube.authentication import auth as myauth
from datetime import datetime
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from urllib.parse import unquote
from flask import json

from assetscube.common import configs as config
import os
import hashlib
import hmac
import binascii
import string
import random
import json

@bp_appfunc.route("/appregis",methods=["GET","POST","OPTIONS"])
def login():
    if request.method=="OPTIONS":
        print("inside login options")
        return "inside login options"

    elif request.method=="POST":
        payload = request.get_json()
        print(payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        dtkn = jwtf.decodetoken(request, needtkn = False)
        userid = dtkn.get("user_id", None)
        entityid = request.headers.get("entityid", None)
        cntryid = request.headers.get("countryid", None)
        
        criteria_json = {
            "userid"   : userid,
            "entityid" : entityid,
            "cntryid"  : cntryid,
            "payload" : payload
        }
        res_to_send, response = app_register(criteria_json)

        if res_to_send == 'success':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        
        return resps

def app_register(criteria_json):
    print("inside login GET")
    s = 0
    f = None
    t = None #message to front end
    response = None
    res_to_send = 'fail'
    payload = criteria_json.get("payload",None)
    
    print(s)
    if s <= 0:
        if criteria_json.get("userid", None) != None:
            userid = criteria_json['userid']
        else:
            userid = None
            s, f, t= errhand.get_status(s, 100, f, "user id not provided", t, "yes")

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
            if payload.get("appname", None) != None:
                appname = payload['appname']
            else:
                appname = None
                s, f, t= errhand.get_status(s, 100, f, "No App name provided", t, "yes")

            if payload.get("appusertype", None) != None:
                appusertype = payload['appusertype']
            else:
                appusertype = None
                s, f, t= errhand.get_status(s, 100, f, "App user type not provided", t, "yes")

            if payload.get("redirecturi", None) != None:
                redirecturi = payload['redirecturi']
            else:
                redirecturi = None
                s, f, t= errhand.get_status(s, 100, f, "Redirect URI not provided", t, "yes")
                    
            if payload.get("postbackuri", None) != None:
                postbackuri = payload['postbackuri']
            else:
                postbackuri = None
                s, f, t= errhand.get_status(s, 0, f, "postbackuri not provided", t, "no")

            if payload.get("description", None) != None:
                description = payload['description']
            else:
                description = None
                s, f, t= errhand.get_status(s, -100, f, "description not provided", t, "no")

            if payload.get("starmfdet", None) != None:
                starmfdet = payload['starmfdet']
            else:
                starmfdet = None
                if appusertype not in ['D','A']:
                    s, f, t= errhand.get_status(s, -100, f, "star mf data not provided", t, "yes")       
                else:
                    s, f, t= errhand.get_status(s, -100, f, "star mf data not provided", t, "no")

            if payload.get("product", None) != None:
                product = payload['product']
            else:
                product = None
                s, f, t= errhand.get_status(s, -100, f, "product not provided", t, "no")
            
            if payload.get("operation", None) != None:
                operation = payload['operation']
            else:
                operation = None
                s, f, t= errhand.get_status(s, -100, f, "operation not provided", t, "no")
            # update or create are the values

            if operation == "delete" or operation == "update":
                if payload.get("appid", None) != None:
                    appid = payload['appid']
                else:
                    appid = None
                    s, f, t= errhand.get_status(s, -100, f, "appid not provided", t, "no")
                
                if payload.get("appkey", None) != None:
                    appkey = payload['appkey']
                else:
                    appkey = None
                    s, f, t= errhand.get_status(s, -100, f, "appkey not provided", t, "no")
            else:
                appid = None
                appkey = None
        
        if appusertype == 'T':
            approved = 'N'
        else:
            approved = 'Y'
    
    print(appid,"oiipoi", appkey)
    cur_time = datetime.now().strftime('%Y%m%d%H%M%S')
    print(appname,appusertype,redirecturi,postbackuri,description,starmfdet)

    if s <= 0:
        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print("connection statment done", s,f,t)
    

    if s <= 0:
        command = cur.mogrify("""
                                SELECT count(1)
                                FROM ncapp.appdetail a
                                WHERE delflg != 'Y'
                                AND (
                                        appname = %s
                                    )
                                AND appuserid = %s AND entityid = %s AND countryid = %s
                            """,(appname, userid, entityid, cntryid,) )
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

    if s <= 0:
        db_rec = cur.fetchall()[0][0]
        print(db_rec)
    
        if db_rec > 0:
            if operation == "create":
                s, f, t= errhand.get_status(s, 100, f, "App name Already exists for this user", t, "yes")
            
        else:
            if operation == "update" or operation == "delete":
                s, f, t= errhand.get_status(s, 100, f, "App name doesn't exists for this user", t, "yes")
            print("no records satifying the current user inputs")
    print(s,f)

    appikset = False
    i = 0
    if s <= 0 and operation == "create":
        while i < 50:
            r = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(6))
            appid = create_signature("sha256", "nirunidhaappid" + r, userid + cur_time, userid)
            appkey = create_signature("md5", "nirunidhaappkey" + r, userid + cur_time, userid)

            command = cur.mogrify("""
                                    SELECT count(1)
                                    FROM ncapp.appdetail
                                    WHERE delflg != 'Y'
                                    AND (
                                            appid = %s OR appkey = %s
                                        )
                                """,(appid, appkey,) )
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

            if s <= 0:
                db_rec = cur.fetchall()[0][0]
                print(db_rec)
            
                if db_rec > 0:
                    s, f, t= errhand.get_status(s, 100, f, "Appid or key Already exists for retrying time: " + i, t, "no")
                    i = i + 1
                    continue
                else:
                    print("no records satifying the current user inputs")
                    appikset = True
                    break
            else:
                # Some error occured, so no point looping
                appikset = False
                break
    print(s,f, t)

    if s <= 0 and operation == "create" and appikset:
        s1, f1 = db.mydbbegin(con, cur)
        print(s1,f1)

        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None

        if s <= 0:
            command = cur.mogrify("""
                        INSERT INTO ncapp.appdetail (appname, appusertype, redirecturi, postbackuri, description, starmfdet, appid, appkey, expirydate, approved, product, delflg, appuserid, octime, lmtime, entityid, countryid) 
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,CURRENT_DATE + INTERVAL'1 month', %s, %s, 'N',%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,%s,%s);
                        """,(appname, appusertype, redirecturi, postbackuri, description, starmfdet, appid, appkey, approved, product, userid, entityid, cntryid,))
            print(command)
            print(appname,appusertype,redirecturi,postbackuri,description,starmfdet,userid)
            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s > 0:
                s, f, t= errhand.get_status(s, 200, f, "SIGNUP update failed", t, "no")

            print('Insert or update is successful')
    
        if s <= 0:
            con.commit()
            #validate PAN adn store PAN number

    if s <= 0 and operation == "update":
        s1, f1 = db.mydbbegin(con, cur)
        print(s1,f1)

        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None

        if s <= 0:
            command = cur.mogrify("""
                        UPDATE ncapp.appdetail SET redirecturi = %s, postbackuri = %s, description = %s, starmfdet = %s, lmtime = CURRENT_TIMESTAMP
                        WHERE  appname = %s AND appusertype = %s AND appid =%s AND appkey = %s AND product = %s AND appuserid = %s AND entityid = %s AND countryid = %s;
                        """,(redirecturi, postbackuri, description, starmfdet, appname, appusertype, appid, appkey, product, userid, entityid, cntryid,))
            print(command)
            print(appname,appusertype,redirecturi,postbackuri,description,starmfdet,userid)
            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s > 0:
                s, f, t= errhand.get_status(s, 200, f, "APP details update failed", t, "no")

            print('Insert or update is successful')
    
        if s <= 0:
            con.commit()
            print("commit done")
            #validate PAN adn store PAN number


    if s <= 0 and operation == "delete":
        s1, f1 = db.mydbbegin(con, cur)
        print(s1,f1)

        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None

        if s <= 0:
            command = cur.mogrify("""
                        UPDATE ncapp.appdetail SET delflg = 'Y', lmtime = CURRENT_TIMESTAMP
                        WHERE  appname = %s AND appusertype = %s AND appid =%s AND appkey = %s AND product = %s AND appuserid = %s AND entityid = %s AND countryid = %s;
                        """,(appname, appusertype, appid, appkey, product, userid, entityid, cntryid,))
            print(command)
            print(appname,appusertype,redirecturi,postbackuri,description,starmfdet,userid)
            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s > 0:
                s, f, t= errhand.get_status(s, 200, f, "APP details update failed", t, "no")

            print('Insert or update is successful')
    
        if s <= 0:
            con.commit()
            #validate PAN adn store PAN number
    usrmg_fstr = None
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
        result_date = [{'appname': appname, 'appid': appid}]
        print("**********************")
        print(operation)
        print("**********************")
        if operation == "create":
            usrmg_fstr = ") creation is successful"  
        elif operation == "update":
            usrmg_fstr = ") updation is successful"
        elif operation == "delete":
            usrmg_fstr = ") deletion is successful"

        response = {
                    'result_data' : result_date,
                    'status': res_to_send,
                    'status_code': 0,
                    'usrmsg': 'App (' + appname + usrmg_fstr
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



@bp_appfunc.route("/appdetail",methods=["POST","OPTIONS"])
@bp_appfunc.route("/appnldetail",methods=["POST","OPTIONS"])
def appdetail():
    if request.method=="OPTIONS":
        print("inside login options")
        return "inside login options"

    elif request.method=="POST":        
        payload = request.get_json()
        print("---------------------3443-----")
        print(payload)
        print("---------------------3443-----")
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        dtkn = jwtf.decodetoken(request, needtkn = False)
        userid = dtkn.get("user_id", None)
        entityid = request.headers.get("entityid", None)
        cntryid = request.headers.get("countryid", None)
        #appid = payload.get("appid", None)

        print("iamback")
        print(userid)
        print(entityid)
        criteria_json = {
            "userid"   : userid,
            "entityid" : entityid,
            "cntryid"  : cntryid,
            "payload" : payload
        }

        res_to_send, response = app_detail_fetch(criteria_json)

        if res_to_send == 'success':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        
        return resps


def app_detail_fetch(criteria_json):
# payload = {'appid': xyz, 'login': <[noauth] to get data without user id>}
# entity id and country id will come in header which are mandator. user id comes in jwt
# Output =  { 'result_data' : [success -> ncapp.appdetail] [Failure -> ""]
#             'status': success/fail,  'status_code': 0,     'usrmsg': ''/error message }
    print("inside app_detail_fetch common function")
    s = 0
    f = None
    t = None #message to front end
    payload = criteria_json.get("payload",None)
    print(payload)

    if s <= 0:
        if payload == None:
            appid = None
            login = None
            # s, f, t= errhand.get_status(s, 100, f, "no payload provided", t, "yes")
        else:
            if payload.get("appid", None) != None:
                appid = payload['appid']
            else:
                appid = None

            if payload.get("login", None) != None:
                login = payload['login']
            else:
                login = None
        print(appid, login, s)
    
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

        if login != "nologin":
            if criteria_json.get("userid", None) != None:
                userid = criteria_json['userid']
            else:
                # To get app details before login for entity and cntry
                userid = None
                s, f, t= errhand.get_status(s, 100, f, "user id not provided", t, "yes")
        else:
                userid = None
                
       
    if s <= 0:
        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        

    if s <= 0:
        if appid == None:
            command = cur.mogrify("""
                                    SELECT json_agg(a) FROM (
                                    SELECT *,
                                            CASE 
                                            WHEN expirydate < CURRENT_TIMESTAMP THEN 'EXPIRED'
                                            ELSE 'ACTIVE'
                                            END AS appexp
                                    FROM ncapp.appdetail                                
                                    WHERE appuserid = %s AND entityid = %s AND countryid = %s
                                    AND delflg = 'N'
                                    ) as a
                                """,(userid,entityid,cntryid,))
        elif userid == None:
            command = cur.mogrify("""
                                    SELECT json_agg(a) FROM (
                                    SELECT *,
                                            CASE 
                                            WHEN expirydate < CURRENT_TIMESTAMP THEN 'EXPIRED'
                                            ELSE 'ACTIVE'
                                            END AS appexp                                    
                                    FROM ncapp.appdetail                                
                                    WHERE appid = %s AND entityid = %s AND countryid = %s
                                    AND delflg = 'N'
                                    ) as a
                                """,(appid,entityid,cntryid,))
        else:
            command = cur.mogrify("""
                                    SELECT json_agg(a) FROM (
                                    SELECT *,
                                            CASE 
                                            WHEN expirydate < CURRENT_TIMESTAMP THEN 'EXPIRED'
                                            ELSE 'ACTIVE'
                                            END AS appexp                                    
                                    FROM ncapp.appdetail                                
                                    WHERE appuserid = %s AND entityid = %s AND countryid = %s AND appid = %s
                                    AND delflg = 'N'
                                    ) as a
                                """,(userid,entityid,cntryid,appid,))

        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "APP data fetch failed with DB error", t, "no")
    print(s,f)

    if s <= 0:
        db_json_rec = cur.fetchall()[0][0]
        print(db_json_rec)


    if s > 0:
        res_to_send = 'fail'
        response = {
            'result_data' : "",
            'status': res_to_send,
            'status_code': s,
            'usrmsg': errhand.error_msg_reporting(s, t)
            }
    else:
        res_to_send = 'success'
        response = {
                    'result_data' : db_json_rec,
                    'status': res_to_send,
                    'status_code': 0,
                    'usrmsg': ''
        }

    print(res_to_send, response)
    
    return (res_to_send, response)


@bp_appfunc.route("/ncappauth",methods=["GET","POST","OPTIONS"])
def ncappauth():
    if request.method=="OPTIONS":
        print("inside ncappauth options")
        return "inside ncappauth options"

    elif request.method=="GET":
        print("inside ncappauth post")
        payload = request.args
        payload = payload.to_dict()
        #payload = request.get_json()
        print("payload",payload)
        #print("payload to dictt",payload.to_dict())
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
        criteria_json = {
            "userid"   : None,
            "entityid" : 'NAWALCUBE',
            "cntryid"  : 'IN',
            "payload" : payload
        }
        res_to_send, appname = other_app_register(criteria_json)
        # success -->  {"appname": app_details["appname"]}
        # failure -->  {"usrmsg": usrmsg}
        print(res_to_send, appname)
        print(payload)
        print("@@@@@@@@@@@@@@@@@@@2")
        if res_to_send == 'success':
            print(config.SIGNUPURL[config.LIVE])
            print(payload["appid"])
            print(appname["appname"])
            print(payload["type"])
            if payload["type"] == "signup":
                return redirect(config.SIGNUPURL[config.LIVE]+"?type=signup&appid="+payload["appid"]+"&appname="+appname["appname"]+"&home="+payload["home"], code=302)
            elif payload["type"] == "code":
                print('inside code')
                print(config.LOGINURL[config.LIVE]+"?type=code&appid="+payload["appid"]+"&redirecturi="+payload["redirecturi"])
                return redirect(config.LOGINURL[config.LIVE]+"?type=code&appid="+payload["appid"]+"&redirecturi="+payload["redirecturi"], code=302)            
            # resps = make_response(jsonify(response), 200)
            # resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            print("inside exit")
            print(appname["usrmsg"])
            print(payload["redirecturi"]+"?type="+payload["type"]+"&regdata=401&msg="+appname["usrmsg"])
            return redirect(payload["redirecturi"]+"?type="+payload["type"]+"&regdata=401&msg="+appname["usrmsg"], code=302)








#http://localhost:8080/appsignup?type=signup&appid=12323235565656&home=http://localhost:4200
@bp_appfunc.route("/ncappsignup",methods=["GET","POST","OPTIONS"])
def ncappsignup():
    if request.method=="OPTIONS":
        print("inside ncappsignup options")
        return "inside ncappsignup options"

    elif request.method=="GET":
        print("inside ncappsignup post")
        payload = request.args
        #payload = request.get_json()
        print("payload",payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))



        criteria_json = {
            "userid"   : None,
            "entityid" : 'NAWALCUBE',
            "cntryid"  : 'IN',
            "payload" : payload
        }
        res_to_send, appname = other_app_register(criteria_json)
        # success -->  {"appname": app_details["appname"]}
        # failure -->  {"usrmsg": usrmsg}
        print(res_to_send, appname)
        if res_to_send == 'success':
            print(config.SIGNUPURL[config.LIVE])
            print(payload["appid"])
            print(appname["appname"])
            print(payload["home"])
            return redirect(config.SIGNUPURL[config.LIVE]+"?type=signup&appid="+payload["appid"]+"&appname="+appname["appname"]+"&home="+payload["home"], code=302)
            # resps = make_response(jsonify(response), 200)
            # resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            print(appname["usrmsg"])
            return redirect(payload["redirecturi"]+"?type=signup&regdata=401&msg="+appname["usrmsg"], code=302)

def other_app_register(criteria_json):
    print("inside other_app_register")
    s = 0
    f = None
    t = None #message to front end
    ret_resp_data = None
    res_to_send = 'fail'
    print('bf')
    print(criteria_json)
    parameters = criteria_json.get("payload",None)
    print(parameters)
    print('sdsds')
    #print(parameters['type'])
    print('sdsds')
    payload = {
        'appid':  parameters['appid'],
        'login':  'nologin'
    }
    print(payload)
    print(criteria_json)
    criteria_json = {
            "userid"   : None,
            "entityid" : criteria_json['entityid'],
            "cntryid"  : criteria_json['cntryid'],
            "payload" : payload
        }
    resp_status, app_data = app_detail_fetch(criteria_json)
    usrmsg = None
    #resp_status = "success"#testcode
    #app_data["result_data"] = {"appname": "kumar"}#testcode
    print(resp_status, app_data)
    if resp_status == "success":
        if app_data["result_data"] != None:
            app_details = app_data["result_data"][0]
            if app_details["appusertype"] == "T":
                res_to_send = "success"
                ret_resp_data = {"appname": app_details["appname"]}
                usrmsg = app_data["usrmsg"]
                
                print('app_details["redirecturi"]')
                print(app_details["redirecturi"])
                print(parameters["redirecturi"])
                print('parameters["redirecturi"]')                
                if app_details["redirecturi"] != parameters["redirecturi"]:
                    res_to_send = "fail"
                    usrmsg = "Redirecturi validation failed"
            else:
                res_to_send = "fail"
                usrmsg = "App is not a Trusted app"

            if app_details["approved"] == "N":
                res_to_send = "fail"
                usrmsg = "App is not a Approved app"
        else:
            usrmsg = "This is not a registered app"

    if res_to_send != "success":
        res_to_send = "fail"
        ret_resp_data = {"usrmsg": usrmsg}

    print(res_to_send, ret_resp_data)
    print("end of other_app_register")
    return res_to_send, ret_resp_data


@bp_appfunc.route("/ncappsingupres",methods=["GET","POST","OPTIONS"])
def ncappsingupres():
    if request.method=="OPTIONS":
        print("inside ncappsingupres options")

        response1 = make_response(jsonify("inside ncappsingupres options"))
        '''
        del response1.headers["entityid"]
        del response1.headers["countryid"]
        response1.headers['Origin'] = "http://localhost:4201"
        response1.headers['Access-Control-Allow-Origin'] = "*"
        response1.headers['Access-Control-Allow-Methods'] = "GET, POST, PATCH, PUT, DELETE, OPTIONS"
        response1.headers['Access-Control-Allow-Headers'] = "Origin, entityid, Content-Type, X-Auth-Token, countryid"
        '''
        return response1

    elif request.method=="POST":
        print("inside ncappsingupres POST")
        payload = request.get_json()
        print("payload")
        print(payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        if payload["restyp"] == "success":
            # firebase auth setup
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
            user = auth.get_user_by_email(email,app=default_app)
            print('Successfully fetched user data: {0}'.format(user.uid))
            userid = user.uid

        entityid = request.headers.get("entityid", None)
        cntryid = request.headers.get("countryid", None)
        appid = payload["appid"]
        payload_to = {"appid": appid, "login": "nologin"}
        criteria_json = {
            "userid"   : None,
            "entityid" : entityid,
            "cntryid"  : cntryid,
            "payload" : payload_to
        }
        print (criteria_json)
        print (payload_to)
        resp_status, app_data = app_detail_fetch(criteria_json)
        app_details = app_data["result_data"][0]
        usrmsg = None
        print("app details")
        print(app_details)
        print(payload)
        if payload["restyp"] == "success":
            if resp_status == "success":
                if app_data["result_data"] != None or app_data["result_data"] != "":
                    res_to_send = "success"
                    redir_ur = app_details["redirecturi"]
                    usrmsg = app_data["usrmsg"]

            if res_to_send != "success":
                res_to_send = "fail"
                redir_ur = app_data["redirecturi"]
                if app_data["usrmsg"] == '' or app_data["usrmsg"] == None:
                    usrmsg = "App id not registered with nawalcube"
                else:
                    usrmsg = app_data["usrmsg"]
        else:
            res_to_send = "fail" 
            usrmsg = payload["msg"]
            

        if res_to_send == "success":
            # Generate authtoken for the user as this is trusted app.  
            # This is to be send by trusted app whenever they communicate
            
            criteria_json = {
                "entityid" : entityid,
                "cntryid"  : cntryid,
                "payload" : {"appid": appid,"redirecturi": redir_ur,"userid": userid}
            }
            print(criteria_json)
            ath_tkn_status, ath_tkn_detail = myauth.app_userauth(criteria_json)
            print("ath_tkn_detail")
            print(ath_tkn_detail)

            if ath_tkn_status == "success":
                urls = {
                    "url": app_details["redirecturi"] + '?type=signup&regdata='+ ath_tkn_detail["result_data"]["authtkn"] +'&msg=success'
                }
            else:
                ath_tkn_status = "fail"
                usrmsg = "User registration key generation failed.  Contact support."
        else:
            ath_tkn_status = "fail"

        if res_to_send != "success" or ath_tkn_status != "success":
            urls = {
                     "url": app_details["redirecturi"] + "?type=signup&regdata=401&msg="+ usrmsg
                    }
        response1 = make_response(jsonify(urls), 200)
        print("end of inside ncappsingupres POST")
        print(response1)
        return response1


@bp_appfunc.route("/ncappfetchfrmtkn",methods=["GET","POST","OPTIONS"])
def ncappfetchfrmtkn():
    # Description : Fetch the singup data
    # Functional use :
    # Called from : callbackurifun.py->ncappfetchfrmtkn
    # Request data:
    # headers = {"entityid": entityid, "countryid": countryid}
    # req_payload = #{"userauthtkn": callback_data["regdata"], "appid": settings.NCAPPID,"appkey":settings.NCAPPKEY}
    # Response from this endpoint:
    #     Field Name         success                     fail
    # -----------------------------------------------------------
    #  {  
    #    "userauthtkn":  new_userauthtkn,                BLANK
    #     "tknexpiry":   usr_db_rec["tknexpiry"],        BLANK
    #     "userid":      more_usr_db_rec["userid"],      BLANK
    #     "username":    more_usr_db_rec["username"],    BLANK
    #     "emailid":     more_usr_db_rec["sinupemail"],  BLANK
    #     "status":      success                         fail
    #     "msg":         BLANK                           fail message
    #   }
    # called functions: 1
    # 1) fetch_app_data_only_wth_tkn(criteria_json)


    if request.method=="OPTIONS":
        print("inside ncappfetchfrmtkn options")        
        response1 = make_response(jsonify("inside ncappfetchfrmtkn options"),200)
        #response1.headers.add("Access-Control-Allow-Headers", "Origin, entityid, Content-Type, X-Auth-Token, countryid")
        return response1

    elif request.method=="POST":
        print("inside ncappsignupfetch POST")
        daa = request.data
        print("daa", daa)
        print(format(daa))
        payload = json.loads(daa.decode("utf-8"))
        #Payload
        #{"userauthtkn": callback_data["regdata"], "appid": settings.NCAPPID,"appkey":settings.NCAPPKEY}

        print("payload")
        print(payload)
        print(type(payload))
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        entityid = request.headers.get("entityid", None)
        countryid = request.headers.get("countryid", None)
        criteria_json = {
            "entityid": entityid,
            "countryid": countryid,
            "payload": payload
        }
        res_status, res_data = fetch_app_data_only_wth_tkn(criteria_json)
        print(res_data)
        #res_data 
        #    Field Name         success                     fail
        #-----------------------------------------------------------
        # {  
        #   "userauthtkn":  new_userauthtkn,                BLANK
        #    "tknexpiry":   usr_db_rec["tknexpiry"],        BLANK
        #    "userid":      more_usr_db_rec["userid"],      BLANK
        #    "username":    more_usr_db_rec["username"],    BLANK
        #    "emailid":     more_usr_db_rec["sinupemail"],  BLANK
        #    "status":      success                         fail
        #    "msg":         BLANK                           fail message
        #  }

        if res_status == "success":
            response1 = make_response(jsonify(res_data),200)
        else:
            response1 = make_response(jsonify(res_data),400)
        
        return response1


def fetch_app_data_only_wth_tkn(criteria_json):
    # Description : Fetch app data
    # Functional use :
    # Called from : appfuncs.py->ncappfetchfrmtkn
    # Request data <criteria_json>:
    # criteria_json = {"entityid": entityid, "countryid": countryid, "payload": <as per below>}
    #         payload = {"userauthtkn": callback_data["regdata"], "appid": settings.NCAPPID,"appkey":settings.NCAPPKEY}
    # Response from this endpoint:
    #     Field Name         success                     fail
    # -----------------------------------------------------------
    #  {  
    #    "userauthtkn":  new_userauthtkn,                BLANK
    #     "tknexpiry":   usr_db_rec["tknexpiry"],        BLANK
    #     "userid":      more_usr_db_rec["userid"],      BLANK
    #     "username":    more_usr_db_rec["username"],    BLANK
    #     "emailid":     more_usr_db_rec["sinupemail"],  BLANK
    #     "status":      success                         fail
    #     "msg":         BLANK                           fail message
    #   }
    # called functions: None

        
    print("inside fetch_app_data_only_wth_tkn function")
    s = 0
    f = None
    t = None #message to front end
    print(criteria_json)
    payload = criteria_json.get("payload",None)
    print(payload)

    if payload == None:
        appid = None
        appkey = None
        userauthtkn = None

        # s, f, t= errhand.get_status(s, 100, f, "no payload provided", t, "yes")
    else:
        if payload.get("appid", None) != None:
            appid = payload['appid']
        else:
            appid = None
            s, f, t= errhand.get_status(s, 100, f, "appid not provided", t, "yes")

        if payload.get("appkey", None) != None:
            appkey = payload['appkey']
        else:
            appkey = None
            s, f, t= errhand.get_status(s, 100, f, "appkey not provided", t, "yes")

        if payload.get("userauthtkn", None) != None:
            userauthtkn = payload['userauthtkn']
        else:
            userauthtkn = None
            s, f, t= errhand.get_status(s, 100, f, "usertoken is not provided", t, "yes")
    print(appid, appkey, userauthtkn)

    if s <= 0:
        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print("DB connection established", s,f,t)
    

    if s <= 0:
        command = cur.mogrify("""
                                SELECT json_agg(a) FROM (
                                SELECT *
                                FROM ncusr.userauth
                                WHERE tknexpiry >= current_timestamp
                                AND appid = %s AND userauthtkn = %s
                                AND entityid = %s AND countryid = %s
                                ) as a
                            """,(appid, userauthtkn, config.INSTALLDATA[config.LIVE]["entityid"],config.INSTALLDATA[config.LIVE]["countryid"],) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "User auth token data fetch failed with DB error", t, "no")
    print(s,f)
    
    usr_db_rec = None
    if s <= 0:
        usr_db_rec = cur.fetchall()[0][0]
        print(usr_db_rec)
        if usr_db_rec != None:
            print(len(usr_db_rec)) 
    
        if usr_db_rec == None or len(usr_db_rec) < 1:
            s, f, t= errhand.get_status(s, 100, f, "User auth token is not valid", t, "yes")            
        else:
            usr_db_rec = usr_db_rec[0]
            print("Userauth token verified successfully")
            pass            
    
    print(s,f)


    if s <= 0:
        command = cur.mogrify("""
                                SELECT json_agg(a) FROM (
                                SELECT *
                                FROM ncapp.appdetail
                                WHERE appid = %s AND appkey = %s
                                AND entityid = %s AND countryid = %s
                                AND delflg != 'Y'
                                ) as a
                            """,(appid, appkey, config.INSTALLDATA[config.LIVE]["entityid"],config.INSTALLDATA[config.LIVE]["countryid"],) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "User auth token data fetch failed with DB error", t, "no")
    print(s,f)
    
    app_db_rec = None
    if s <= 0:
        app_db_rec = cur.fetchall()[0][0]
        print(app_db_rec)
        if app_db_rec != None:
            print(len(app_db_rec))
    
        if app_db_rec == None or len(app_db_rec) < 1:
            s, f, t= errhand.get_status(s, 100, f, "App id is not valid", t, "yes")            
        else:
            app_db_rec = app_db_rec[0]
            if app_db_rec["approved"] == 'N':
                s, f, t= errhand.get_status(s, 100, f, "App id not approved yet", t, "yes")
            else:                
                print("App id verified successfully")
    
    print(s,f)

    if s <= 0:
        command = cur.mogrify("""
                                SELECT json_agg(a) FROM (
                                SELECT *
                                FROM ncusr.userdetails a, ncusr.userlogin b
                                WHERE a.userid = %s AND a.entityid = %s AND a.countryid = %s
                                AND a.userid = b.userid AND a.entityid = b.entityid AND a.countryid = b.countryid
                                ) as a
                            """,(usr_db_rec["userid"],  config.INSTALLDATA[config.LIVE]["entityid"],config.INSTALLDATA[config.LIVE]["countryid"],) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "User details data fetch failed with DB error", t, "no")
    print(s,f)
    
    more_usr_db_rec = None
    if s <= 0:
        more_usr_db_rec = cur.fetchall()[0][0]
        print(more_usr_db_rec)
        print(len(more_usr_db_rec))
    
        if more_usr_db_rec == None or len(more_usr_db_rec) < 1:
            s, f, t= errhand.get_status(s, 100, f, "User details not available for the given auth token", t, "yes")            
        else:
            more_usr_db_rec = more_usr_db_rec[0]
            print("user details fetched successfully")
            pass            
    
    print(s,f)

    if s <= 0:
        #Validate the user status
        if more_usr_db_rec["userstatus"] == 'B':
            #B-Blocked , I-Deleteduser
            s, f, t= errhand.get_status(s, 100, f, "User is blocked", t, "yes")
        elif more_usr_db_rec["userstatus"] == 'I':
            #B-Blocked , I-Deleteduser
            s, f, t= errhand.get_status(s, 100, f, "User is Deleted", t, "yes")


    if s <= 0:
        data_to_auth_tkn = {
            "entityid": config.INSTALLDATA[config.LIVE]["entityid"],          
            "cntryid" : config.INSTALLDATA[config.LIVE]["countryid"],
            "payload" : {
                        "appid" : app_db_rec["appid"],
                        "redirecturi" : app_db_rec["redirecturi"],
                        "userid" : more_usr_db_rec["userid"]
                        }
        }
    
        ath_tkn_status, ath_tkn_detail = myauth.app_userauth(data_to_auth_tkn)
        print("new ath_tkn_detail")
        print(ath_tkn_detail)

        if ath_tkn_status == "success":
            s, f, t= errhand.get_status(s, 0, f, "User auth token regenerated", t, "no")
            new_userauthtkn = ath_tkn_detail["result_data"]["authtkn"]
            print(new_userauthtkn)
        else:
            s, f, t= errhand.get_status(s, 100, f, "error in User auth token regeneration", t, "no")
            new_userauthtkn = None

    res_status = None
    if s <= 0:
        res_status = "success"
        user_auth_detais = {
            "userauthtkn": new_userauthtkn,
            "tknexpiry": usr_db_rec["tknexpiry"],
            "userid": more_usr_db_rec["userid"],
            "username": more_usr_db_rec["username"],
            "emailid": more_usr_db_rec["sinupemail"],
            "status": res_status,
            "msg":""
        }
    else:
        res_status = "fail"
        user_auth_detais = {
            "userauthtkn": "",
            "userid": "",
            "username": "",
            "emailid": "",
            "status": res_status,
            "msg": t
        }
    print("rached end")
    return res_status, user_auth_detais