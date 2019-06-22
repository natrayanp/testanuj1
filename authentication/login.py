from . import bp_auth, bp_login
from flask import redirect, request,make_response, jsonify
#from flask_cors import CORS, cross_origin
from assetscube.common import dbfunc as db
from assetscube.common import error_logics as errhand
from assetscube.common import jwtfuncs as jwtf
from assetscube.common import serviceAccountKey as sak
from assetscube.common import configs as configs
from datetime import datetime
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
import os
import hashlib
import json
import requests
import time


@bp_auth.route("/tstnatlogin")
@bp_login.route("/tstnatlogin",methods=["GET","OPTIONS"])
def tstnatlogin():
    if request.method=="OPTIONS":
        print("inside tstlogin options")
        return "inside tstlogin options"

    elif request.method=="GET":
        #res_to_send, response = login_common(request, 'nc')
        time.sleep(5)
        res_to_send = 'success'
        if res_to_send == 'success':
            resps = make_response(jsonify({'nat': 'success'}), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            #resps = make_response(jsonify(response), 400)
            print("end")
    print("end")
    return resps


@bp_auth.route("/login")
@bp_login.route("/login",methods=["GET","OPTIONS"])
def login():
    if request.method=="OPTIONS":
        print("inside login options")
        return "inside login options"

    elif request.method=="GET":
        res_to_send, response = login_common(request, 'nc')

        if res_to_send == 'success' or 'fail':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        #dfdfdf
        return resps

@bp_login.route("/dvlogin",methods=["GET","OPTIONS"])
def dvlogin():
    if request.method=="OPTIONS":
        print("inside dvlogin options")
        return "inside dvlogin options"

    elif request.method=="GET":
        res_to_send, response = login_common(request, 'dv')

        if res_to_send == 'success':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        
        return resps


def login_common(request, site):
    print("inside login GET")
    s = 0
    f = None
    t = None #message to front end
    response = None
    res_to_send = 'fail'
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    dtkn = jwtf.decodetoken(request, needtkn = False)
    userid = dtkn.get("user_id", None)
    entityid = request.headers.get("entityid", None)
    cntryid = request.headers.get("countryid", None)

    print("iamback")
    print(userid)
    print(entityid)

    if userid == None:
        s, f, t= errhand.get_status(s, 100, f, "No user details sent from client", t, "yes")
    if entityid == None:
        s, f, t= errhand.get_status(s, 100, f, "No entity details sent from client", t, "yes")
    if cntryid == None:
        s, f, t= errhand.get_status(s, 100, f, "No country details sent from client", t, "yes")
    
    ipaddress = ''

    
    if s <= 0:
        sh = session_hash( userid + datetime.now().strftime("%Y%m%d%H%M%S%f"))
        print("session_has", sh)

        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
    
    if s <= 0:
        command = cur.mogrify("""
                                SELECT COUNT(1) FROM ncusr.loginh WHERE
                                userid = %s AND entityid = %s AND countryid = %s
                                AND logoutime IS NULL AND sessionid != %s AND site = %s;
                            """,(userid, entityid, cntryid, sh, site,) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "session data fetch failed with DB error", t, "no")
    print(s,f)

    if s <= 0:
        session_cnt = cur.fetchall()[0][0]
        print(session_cnt)

        if session_cnt > 0:
            s, f, t = errhand.get_status(s, 401, f, "User already have a active session.  Kill all and proceed?",t,"yes")
            res_to_send = 'fail'
            response = {
                'uid' : userid,
                'sessionid' : sh,
                'status': res_to_send,
                'status_code': s,
                'message': errhand.error_msg_reporting(s, t)
                }

        else:
            s1, f1 = db.mydbbegin(con, cur)
            print(s1,f1)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s <= 0:
                command = cur.mogrify("""
                            INSERT INTO ncusr.loginh (userid, ipaddress, sessionid, site, logintime, entityid, countryid) 
                            VALUES (%s,%s,%s,%s,CURRENT_TIMESTAMP,%s,%s);
                            """,(userid, ipaddress, sh, site, entityid, cntryid,))
                print(command)
                cur, s1, f1 = db.mydbfunc(con,cur,command)
                s, f, t= errhand.get_status(s, s1, f, f1, t, "no")  
                s1, f1 = 0, None

                if s > 0:
                    s, f, t= errhand.get_status(s, 200, f, "SIGNUP update failed", t, "no")
                print('Insert or update is successful')

            if s > 0:
                res_to_send = 'fail'
                response = {
                    'uid' : userid,
                    'sessionid' : '',
                    'status': res_to_send,
                    'status_code': s,
                    'message': errhand.error_msg_reporting(s, t)
                    }
            else:
                res_to_send = 'success'
                response = {
                            'uid' : userid,
                            'sessionid' : sh,
                            'status': res_to_send,
                            'status_code': 0,
                            'message': ''
                }

    con.commit()
    print(response)
    
    return (res_to_send, response)
    

def session_hash(password):
    salt = 'sesstkn'
    print(password)
    print(salt)
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest()


@bp_auth.route("/loginks")
@bp_login.route("/dvloginks",methods=["GET","OPTIONS"])
def loginks():
    #This is to kill session if already exists
    if request.method=="OPTIONS":
        print("inside loginks options")
        return "inside loginks options"

    elif request.method=="GET":
        res_to_send, response = loginsk_common(request, 'nc')

        if res_to_send == 'success':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        
        return resps

@bp_login.route("/dvloginks",methods=["GET","OPTIONS"])
def dvloginks():
    if request.method=="OPTIONS":
        print("inside loginks options")
        return "inside loginks options"

    elif request.method=="GET":
        res_to_send, response = loginsk_common(request, 'dv')

        if res_to_send == 'success':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        
        return resps

def loginsk_common(request, site):

    print("inside loginks GET")
    s = 0
    f = None
    t = None #message to front end
    response = None
    res_to_send = 'fail'
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    dtkn = jwtf.decodetoken(request, needtkn = False)
    userid = dtkn.get("user_id", None)
    entityid = request.headers.get("entityid", None)
    cntryid = request.headers.get("countryid", None)

    print("iamback")
    print(userid)
    print(entityid)

    if userid == None:
        s, f, t= errhand.get_status(s, 100, f, "No user details sent from client", t, "yes")
    if entityid == None:
        s, f, t= errhand.get_status(s, 100, f, "No entity details sent from client", t, "yes")
    if cntryid == None:
        s, f, t= errhand.get_status(s, 100, f, "No country details sent from client", t, "yes")
    
    ipaddress = ''

    
    if s <= 0:
        sh = session_hash( userid + datetime.now().strftime("%Y%m%d%H%M%S%f"))
        print("session_has", sh)

    con, cur, s1, f1 = db.mydbopncon()
    s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
    s1, f1 = 0, None

    if s <= 0:
        s1, f1 = db.mydbbegin(con, cur)
        print(s1,f1)
        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None


    if s <= 0:
        command = cur.mogrify("""
                    UPDATE ncusr.loginh SET logoutime = CURRENT_TIMESTAMP
                    WHERE userid = %s AND entityid = %s AND countryid = %s
                    AND logoutime IS NULL AND sessionid != %s and site = %s;
                    """,(userid, entityid, cntryid, sh, site,) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")  
        s1, f1 = 0, None

        if s > 0:
            s, f, t= errhand.get_status(s, 200, f, "INVALIDATING other active session failed", t, "no")
        print('Insert or update is successful')

    if s <= 0:
        command = cur.mogrify("""
                    INSERT INTO ncusr.loginh (userid, ipaddress, sessionid, site, logintime, entityid, countryid) 
                    VALUES (%s,%s,%s,%s,CURRENT_TIMESTAMP,%s,%s);
                    """,(userid, ipaddress, sh, site, entityid, cntryid,))
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")  
        s1, f1 = 0, None

        if s > 0:
            s, f, t= errhand.get_status(s, 200, f, "SIGN IN WITH NEW session failed", t, "no")
        print('Insert or update is successful')

    if s > 0:
        res_to_send = 'fail'
        response = {
            'uid' : userid,
            'sessionid' : '',
            'status': res_to_send,
            'status_code': s,
            'message': errhand.error_msg_reporting(s, t)
            }
    else:
        res_to_send = 'success'
        response = {
                    'uid' : userid,
                    'sessionid' : sh,
                    'status': res_to_send,
                    'status_code': 0,
                    'message': ''
        }

    con.commit()
    print(response)

    return (res_to_send, response)





@bp_auth.route("/logout")
@bp_login.route("/logout",methods=["GET","OPTIONS"])
def logout():
    if request.method=="OPTIONS":
        print("inside logout options")
        return "inside logout options"

    elif request.method=="GET":
        res_to_send, response = logout_common(request, 'nc')
        if res_to_send == 'success':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        
        return resps


@bp_login.route("/dvlogout",methods=["GET","OPTIONS"])
def dvlogout():
    if request.method=="OPTIONS":
        print("inside logout options")
        return "inside logout options"

    elif request.method=="GET":
        res_to_send, response = logout_common(request, 'dv')
        if res_to_send == 'success':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        
        return resps

def logout_common(request, site):

    print("inside logout GET")
    s = 0
    f = None
    t = None #message to front end
    response = None
    res_to_send = 'fail'
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    dtkn = jwtf.decodetoken(request, needtkn = False)
    userid = dtkn.get("user_id", None)
    entityid = request.headers.get("entityid", None)
    cntryid = request.headers.get("countryid", None)
    sh = request.headers.get("mysession", None)

    print("iamback")
    print(userid)
    print(entityid)

    if userid == None:
        s, f, t= errhand.get_status(s, 100, f, "No user details sent from client", t, "yes")
    if entityid == None:
        s, f, t= errhand.get_status(s, 100, f, "No entity details sent from client", t, "yes")
    if cntryid == None:
        s, f, t= errhand.get_status(s, 100, f, "No country details sent from client", t, "yes")
    if sh == None:
        s, f, t= errhand.get_status(s, 100, f, "No session details sent from client", t, "yes")
    
    ipaddress = ''

    con, cur, s1, f1 = db.mydbopncon()
    s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
    s1, f1 = 0, None

    if s <= 0:
        s1, f1 = db.mydbbegin(con, cur)
        print(s1,f1)
        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None


    if s <= 0:
        command = cur.mogrify("""
                    UPDATE ncusr.loginh SET logoutime = CURRENT_TIMESTAMP
                    WHERE userid = %s AND entityid = %s AND countryid = %s
                    AND logoutime IS NULL AND site = %s;
                    """,(userid, entityid, cntryid, site,) )
        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t= errhand.get_status(s, s1, f, f1, t, "no")  
        s1, f1 = 0, None

        if s > 0:
            s, f, t= errhand.get_status(s, 200, f, "LOGOUT UPDATE failed", t, "no")
        print('Insert or update is successful')


    if s > 0:
        res_to_send = 'fail'
        response = {
            'uid' : userid,
            'sessionid' : '',
            'status': res_to_send,
            'status_code': s,
            'message': errhand.error_msg_reporting(s, t)
            }
    else:
        res_to_send = 'success'
        response = {
                    'uid' : userid,
                    'sessionid' : '',
                    'status': res_to_send,
                    'status_code': 0,
                    'message': ''
        }

    con.commit()
    print(response)
    print('logout successful')
    return (res_to_send, response)




@bp_login.route("/signup",methods=["GET","POST","OPTIONS"])
def signup():
    if request.method=="OPTIONS":
        print("inside signup options")
        #response1 = make_response(jsonify("inside signup options"),200)
        #return response1
        return "inside logout options"


    elif request.method=="POST":
        print("inside signup POST")
        s = 0
        f = None
        t = None #message to front end
        payload = request.get_json()
        print(payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
        tkn, dtkn = jwtf.decodetoken(request, needtkn = True)
        token = tkn
        userid = dtkn["user_id"]
        entityid = request.headers.get("entityid", None)
        countryid = request.headers.get("countryid", None)
        print('iamback')
        print(token)
        print(userid)
        print(entityid)

        sign_data = {
            "userid" : userid,
            "entityid" : entityid,
            "countryid" : countryid,
            "payload" : payload,
            "typeoper" : "signupwtkn",
            "token": token
        }   

        respo = signup_common(sign_data)
        print("respo")
        print(respo)
        if respo["status"] == "success" or "fail":
            '''
            respm = {
                'status': respo["status"],
                'error_msg' : respo["error_msg"]
            }
            '''
            resps = make_response(jsonify(respo), 200)
        else:
            '''
            respm = {
                'status': respo["status"],
                'error_msg' : respo["error_msg"]
            }
            '''
            resps = make_response(jsonify(respo), 400)
        return resps


@bp_login.route("/signupnotkn",methods=["GET","POST","OPTIONS"])
def signupnotkn():
    if request.method=="OPTIONS":
        print("inside signupnotkn options")
        response1 = make_response(jsonify("inside signupnotkn options"),200)
        #response1.headers['Access-Control-Allow-Headers'] = "Origin, entityid, Content-Type, X-Auth-Token, countryid"
        #response1.headers.add("Access-Control-Allow-Headers", "Origin, entityid, Content-Type, X-Auth-Token, countryid")
        return response1

    elif request.method=="POST":
        print("inside signupnotkn POST")
        s = 0
        f = None
        t = None #message to front end
        payload = request.get_json()
        print(payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
        entityid = request.headers.get("entityid", None)
        countryid = request.headers.get("countryid", None)
        print('iamback')
        print(entityid)
        print(countryid)

        sign_data = {
            "userid" : None,
            "entityid" : entityid,
            "countryid" : countryid,
            "payload" : payload,
            "typeoper" : "signupnotkn",
            "token": None
        }

        respo = signup_common(sign_data)
        print("respo")
        print(respo)
        if respo["status"] == "success":
            respm = {
                'status': respo["status"],
                'error_msg' : respo["error_msg"]
            }
            resps = make_response(jsonify(respm), 200)
        else:
            respm = {
                'status': respo["status"],
                'error_msg' : respo["error_msg"]
            }
            resps = make_response(jsonify(respm), 400)
        return resps


def signup_common(sign_data):

    print("inside signup_common")
    s = 0
    f = None
    t = None #message to front end
    response = None
    failed_only_here = False

    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


    payload = sign_data["payload"]
    print(payload)

    '''
    usr_payload = sign_data["payload"]["usrpass_frm"]
    '''
    if sign_data["payload"].get("otherapp", None) != None:
        otherapp = sign_data["payload"]['otherapp']
    else:
        otherapp = None
        s, f, t= errhand.get_status(s, 0, f, "other app identifier not sent", t, "no")
  
    if sign_data.get("typeoper", None) != None:
        typeoper = sign_data['typeoper']
    else:
        typeoper = None
        s, f, t= errhand.get_status(s, 100, f, "type of operation not sent", t, "no")
    print(typeoper)
    '''
    if payload.get("custtype", None) != None:
        usercusttype = payload['custtype']['value']
    else:
        usercusttype = None
        s, f, t= errhand.get_status(s, 100, f, "No user customer type from client", t, "yes")

    if payload.get("name", None) != None:
        sinupusername = payload['name']
    else:
        sinupusername = None
        s, f, t= errhand.get_status(s, 100, f, "No user name from client", t, "yes")

    if payload.get("adhaar", None) != None:
        sinupadhaar = payload['adhaar']
    else:
        sinupadhaar = None
        if usercusttype not in ['D','A','T']:                    
            s, f, t= errhand.get_status(s, 100, f, "No adhaar from client", t, "yes")
            
    if payload.get("pan", None) != None:
        sinuppan = payload['pan']
    else:
        sinuppan = None
        if usercusttype not in ['D','A','T']:                    
            s, f, t= errhand.get_status(s, 100, f, "No pan from client", t, "yes")
    
    if payload.get("arn", None) != None:
        sinuparn = payload['arn']
    else:
        sinuparn = None
        if usercusttype not in ["I","P"]:                    
            s, f, t= errhand.get_status(s, 100, f, "No arn from client", t, "yes")

    if payload.get("mobile", None) != None:
        sinupmobile = payload['mobile']
    else:
        sinupmobile = None
        s, f, t= errhand.get_status(s, 100, f, "No mobile data from client", t, "yes")
    '''
    if sign_data.get("entityid",None) != None:
        entityid =  sign_data["entityid"]
    else:
        s, f, t= errhand.get_status(s, 100, f, "No entityid detail from client", t, "yes")
    print(entityid)
    
    if sign_data.get("countryid",None) != None:
        countryid =  sign_data["countryid"]
    else:
        s, f, t= errhand.get_status(s, 100, f, "No countryid detail from client", t, "yes")
    print(countryid)

    if typeoper == "signupwtkn":
        if sign_data.get("userid",None) != None:
            userid =  sign_data["userid"]
        else:
            s, f, t= errhand.get_status(s, 100, f, "No user id detail from client", t, "yes")
        print(userid)

        if sign_data.get("token",None) != None:
            token =  sign_data["token"]
        else:
            s, f, t= errhand.get_status(s, 100, f, "No token detail from client", t, "yes")        
        print(token)

        email = None

    elif typeoper == "signupnotkn":
        #This is for typeoper = "signupnotkn"
        userid = None
        token = None
        if usr_payload.get("email",None) != None:
            email =  usr_payload["email"]
        else:
            s, f, t= errhand.get_status(s, 100, f, "No email detail from client", t, "yes")
    
    else:
        s, f, t= errhand.get_status(s, 100, f, "Type of operation "+ typeoper + "is not handled", t, "no")

    usertype='W'
    userstatus = 'A' #Active user at the time of creation
    userrole = 'W' #Write access for the site
    siteaccessstatus = 'A' #Active user at the time of creation
    uid= None
    #print(sinupadhaar,sinuppan,sinuparn,sinupmobile)
    if s <= 0:
        # firebase auth setup
        try:
            print('inside try')
            default_app=firebase_admin.get_app('natfbloginsingupapp')
            print('about inside try')
        except ValueError:                      
            print('inside value error')
            #cred = credentials.Certificate(os.path.dirname(__file__)+'/serviceAccountKey.json')
            cred = credentials.Certificate(sak.SERVICEAC)
            default_app = firebase_admin.initialize_app(credential=cred,name='natfbloginsingupapp')
        else:
            pass

        print('app ready')

    if typeoper == "signupwtkn" and s <= 0:
        try:
            print('start decode')
            decoded_token = auth.verify_id_token(token,app=default_app)
            print('decoded')
        except ValueError:
            print('valuererror')
            s, f, t = errhand.get_status(s, 100, f, "Not a valid user properties", t, "yes")            
        except AuthError:
            print('AuthError')
            s, f, t = errhand.get_status(s, 100, f, "Not a valid user credentials", t, "yes")     
        else:
            print('inside', decoded_token)
            uid = decoded_token.get("user_id", None)
            exp = decoded_token.get("exp", None)
            iat = decoded_token.get("iat", None)
            email = decoded_token.get("email", None)
            name = decoded_token.get("name", None)

    
    elif typeoper == "signupnotkn" and s <= 0:
        print("inside signupnotkn")
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
    print(entityid)
    '''
    if entityid != None and s <= 0:
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
    else:
        print('else after autherror')
        if entityid == None:
            s, f, t = errhand.get_status(s, 100, f, "No entity id from client", t, "yes")
    '''
    print('apppa mudichachu')
    print(uid)

    if s <= 0:
        if email != None:
            sinupemail = email
        else:
            sinupemail = None
            s, f, t = errhand.get_status(s, 100, f, "No email data from client", t, "yes")

        if uid != None:
            userid = uid
        else:
            userid = None
            s, f, t = errhand.get_status(s, 100, f, "No user id from client" , t, "yes")
        

        if name != None:
            name = name
        else:
            name = None
            s, f, t = errhand.get_status(s, 0, f, "No name details in token" , t, "yes")
        
        
    if s <= 0:
        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        

    if s <= 0:
        '''
        sql = "SELECT json_agg(a) FROM ("
        sql = sql + "SELECT l.userid, l.username, l.usertype, l.usercusttype, l.entityid, "
        sql = sql + "d.sinupusername, d.sinupadhaar, d.sinuppan, d.sinupmobile, d.sinupemail, d.sinuparn "
        sql = sql + "FROM ncusr.userlogin l "
        sql = sql + "LEFT JOIN ncusr.userdetails d ON l.userid = d.userid AND l.entityid = d.entityid "
        sql = sql + "WHERE l.userstatus != 'I' "

        if usercusttype not in ["D","A"]:
            if uid != None or uid != '':
                sql = sql + "AND (l.userid = %s or d.sinupadhaar = %s OR d.sinuppan = %s OR d.sinupmobile = %s OR d.sinupemail = %s) "
            else:
                sql = sql + "AND (d.sinupadhaar = %s OR d.sinuppan = %s OR d.sinupmobile = %s OR d.sinupemail = %s) "


        if usercusttype in ["D","A"]:
            if uid != None or uid != '':
                sql = sql + "AND (l.userid = %s or d.sinuparn = %s) "
            else:
                sql = sql + "AND sinuparn = %s "
        
        sql = sql + "AND l.entityid = %s AND l.countryid = %s) as a"

        if usercusttype not in ["D","A"]:
            if uid != None or uid != '':
                command = cur.mogrify(sql,(uid,sinupadhaar,sinuppan,sinupmobile,sinupemail,entityid,countryid,))
            else:    
                command = cur.mogrify(sql,(sinupadhaar,sinuppan,sinupmobile,sinupemail,entityid,countryid,))

        if usercusttype in ["D","A"]:
            if uid != None or uid != '':
                command = cur.mogrify(sql,(uid,sinuparn,entityid,countryid,))
            else:
                command = cur.mogrify(sql,(sinuparn,entityid,countryid,))

        '''
        command = cur.mogrify("""
                                SELECT json_agg(a) FROM (
                                SELECT l.userid, l.useremail
                                FROM ncusr.userlogin l
                                WHERE l.userstatus != 'D'
                                AND (
                                        l.userid = %s OR l.useremail = %s
                                    )
                                AND l.entityid = %s AND l.countryid = %s
                                ) as a
                            """,(uid,sinupemail,entityid,countryid,) )

        print(command)
        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "User data fetch failed with DB error", t, "no")
    print(s,f)
    pan_payload = None
    
    othapp_res_stat = "success"
    usrmsg = "" 
    insert_or_not = True

    if s <= 0:
        db_json_rec = cur.fetchall()[0][0]
        print(db_json_rec)

        if db_json_rec != None:
            #validate 
            pyld = {
                    "userid" : userid,
                    #"sinupadhaar" : sinupadhaar,
                    #"sinuppan" : sinuppan,
                    #"sinuparn" : sinuparn,
                    #"sinupmobile" : sinupmobile,
                    "sinupemail" : sinupemail,
                    #"usercusttype" : usercusttype
            }

            othapp_res_stat, usrmsg, insert_or_not = allow_regis_user(db_json_rec, pyld, otherapp)


    print("@@@@@@@@@##############$$$$$$$$$$$$$$$$$")
    print(othapp_res_stat )
    print(usrmsg)
    print(insert_or_not )
    print("@@@@@@@@@##############$$$$$$$$$$$$$$$$$")

    '''
    if not insert_or_not:
        usrmsg = usrmsg if usrmsg != "" else "Email id already registered"
        s, f, t= errhand.get_status(s, 110, f, usrmsg, t, "yes")
    '''
    
    if insert_or_not:
        if s <= 0:
            s1, f1 = db.mydbbegin(con, cur)
            print(s1,f1)

            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

        if s <= 0:
            command = cur.mogrify("""
                        INSERT INTO ncusr.userlogin (userid, username, useremail, userstatus, userstatlstupdt, octime, lmtime, entityid, countryid) 
                        VALUES (%s,%s,%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,%s,%s);
                        """,(userid, name, sinupemail, userstatus, entityid, countryid,))
            print(command)
            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s > 0:
                s, f, t= errhand.get_status(s, 200, f, "SIGNUP update failed", t, "no")
            print('Insert or update is successful')

        if s <= 0:
            command = cur.mogrify("""
                        INSERT INTO ncusr.useraccess (userid, site, role, accessstatus, octime, lmtime, entityid, countryid) 
                        VALUES (%s,%s,%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,%s,%s);
                        """,(userid, entityid, userrole, siteaccessstatus, entityid, countryid,))
            print(command)
            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s > 0:
                s, f, t= errhand.get_status(s, 200, f, "SIGNUP update failed", t, "no")

            print('Insert or update is successful')

        if s <= 0:
            con.commit()
            db.mydbcloseall(con, cur)
    '''
    if s <= 0:
        pan_payload = {
            "userid" : userid,
            "entityid" : entityid,
            "cntryid" : countryid,
            "pan" : sinuppan
        }

        status, kyc_data = kyc_detail_update(pan_payload)

        print(kyc_data)
        if status == "success":
            s, f, t = errhand.get_status(s, 0, f, "KYC update success", t, "no")
        else:
            s, f, t = errhand.get_status(s, 0, f, "KYC update failed", t, "no")
    '''

    if othapp_res_stat == "success" and s <= 0:
        response = {
                'uid' : userid,
                'sessionid' : None,
                'status': 'success',
                'status_code': s,
                'message' : ''
            }
        #resps = make_response(jsonify(response), 200)
    else:
        response = {
            'uid' : userid,
            'sessionid' : None,
            'status': 'fail',
            'status_code': s,
            'message' : usrmsg
        }              

    print (response)
    print("#########################################################################################################")
    return response



def allow_regis_user(db_json_rec, pyld, otherapp= False):
    print("inside allow_regis_user")
    stat = "success"
    usrmsg = None
    insert_rec = False
    email_exist = False
    userid_exist = False
    eusrm = ""
    
    for rec in db_json_rec:

        if rec['useremail'] != '':
            if rec['useremail'] == pyld["sinupemail"]:
                #usrm = "Email Already registered" if usrm == None else usrm + " | Email Already registered"
                email_exist = True  # All other values should match
                eusrm = "Email Already registered"
            else:
                email_exist = False # All other values should not exists in rec
                eusrm = ""

        if otherapp:            
            if email_exist:
                all_rec_match, usrmg = chk_if_value_match(rec, pyld, "all", "yes")
                if all_rec_match:
                    stat = "success"
                    usrmsg = usrmg  #--> ""
                    # Don't insert
                    break
                else:
                    stat = "fail"
                    usrmsg = eusrm + "but " + usrmg #--> failed reason
                    # Don't insert
                    break
            else:
                any_rec_match, usrmg = chk_if_value_match(rec, pyld, "any", "yes")
                if any_rec_match:
                    stat = "fail"
                    usrmsg = usrmg #--> failed reason
                    # Don't insert
                    break
                else:
                    stat = "success"
                    usrmsg = usrmg #--> ""
                    insert_rec = True
                    # insert
        else:           
            if rec['userid'] != '':
                if rec['userid'] == pyld["userid"]:
                    #usrms = "Userid Already exists for the Email id" if usrm == None else usrm + " | Userid Already exists for the Email id"
                    userid_exist = True
                else:
                    all_rec_match = False
                    userid_exist = False
                    #usrmf = "Userid doesn't exists for the Email id" if usrmf == None else usrmf + " | Userid doesn't exists for the Email id"

            if email_exist or userid_exist:
                # email already registered or userid already exists
                eusrm = "Email Already registered" if email_exist else ""
                uusrm = "Userid Already exists" if userid_exist else ""
                stat = "fail"
                usrmsg = eusrm + " " + uusrm
                break
                # Don't insert

            elif not email_exist and not userid_exist:
                # email not registered and userid not exists
                any_rec_match, usrmg = chk_if_value_match(rec, pyld, "any", "no")
                if any_rec_match:
                    # email not registered and userid not exists but pan or adhaar or mobile exists
                    stat = "fail"
                    usrmsg = usrmg
                    break
                    # Don't insert
                else:
                    # email not registered and userid not exists and pan,adhaar,mobile not exists
                    stat = "success"
                    usrmsg = ""
                    insert_rec = True
                    # insert

        
    return stat, usrmsg, insert_rec


def chk_if_value_match(rec, pyld, find = "any", include_usr_val = "yes"):
    all_rec_match = True
    any_rec_match = False
    usrms = None
    usrmf = None

    if include_usr_val == "yes":
        if rec['userid'] != '':
            if rec['userid'] == pyld["userid"]:
                usrms = "Userid Already exists for the Email id" if usrms == None else usrms + " | Userid Already exists for the Email id"
                all_rec_match = True if all_rec_match else False
                any_rec_match = True
            else:
                all_rec_match = False
                usrmf = "Userid doesn't exists for the Email id" if usrmf == None else usrmf + " | Userid doesn't exists for the Email id"
    '''
    if rec['sinupadhaar'] != '':
        if rec['sinupadhaar'] == pyld["sinupadhaar"]:
            usrms = "Adhaar Already registered" if usrms == None else usrms + " | Adhaar Already registered"
            all_rec_match = True if all_rec_match else False
            any_rec_match = True
        else:
            all_rec_match = False
            usrmf = "Adhaar doesn't registered" if usrmf == None else usrmf + " | Adhaar doesn't registered"

    if rec['sinuppan'] != '':
        if rec['sinuppan'] == pyld["sinuppan"]:
            usrms = "PAN Already registered" if usrms == None else usrms + " | PAN Already registered"
            all_rec_match = True if all_rec_match else False
            any_rec_match = True
        else:
            all_rec_match = False
            usrmf = "PAN doesn't registered" if usrmf == None else usrmf + " | PAN doesn't registered"

    if rec['sinuparn'] != '':
        if rec['sinuparn'] == pyld["sinuparn"]:
            usrms = "ARN Already registered" if usrms == None else usrms + " | ARN Already registered"
            all_rec_match = True if all_rec_match else False
            any_rec_match = True
        else:
            all_rec_match = False
            usrmf = "ARN doesn't registered" if usrmf == None else usrmf + " | ARN doesn't registered"

    if rec['sinupmobile'] != '':
        if rec['sinupmobile'] == pyld["sinupmobile"]:
            usrms = "Mobile Already registered" if usrms == None else usrms + " | Mobile Already registered"
            all_rec_match = True if all_rec_match else False
            any_rec_match = True
        else:
            all_rec_match = False
            usrmf = "Mobile doesn't registered" if usrmf == None else usrmf + " | Mobile doesn't registered"
    '''

    if find == "all":
        rec_match = all_rec_match
        if all_rec_match:
            usrmsg = ""
        else:
            usrmsg = usrmf

    if find == "any":
        rec_match = any_rec_match
        if any_rec_match:            
            usrmsg = usrms
        else:
            usrmsg = ""


    return rec_match, usrmsg
'''
def validate_app(rec,pyld):

    if rec['sinupemail'] != '':
        if rec['sinupemail'] == pyld["sinupemail"]:
            if not otherapp:
                s, f, t= errhand.get_status(s, 100, f, "Email Already registered", t, "yes")
                stat = "fail"                

    if rec['userid'] != '':
        if rec['userid'] == pyld["userid"]:
            s, f, t= errhand.get_status(s, 100, f, "Userid Already exists for the Email id", t, "yes")                  
            stat = "fail"

    if stat != "fail":
        if rec['sinupadhaar'] != '':           
            if rec['sinupadhaar'] == pyld["sinupadhaar"]:
                s, f, t= errhand.get_status(s, 100, f, "Adhaar Already registered", t, "no")

        if rec['sinuppan'] != '':
            if rec['sinuppan'] == pyld["sinuppan"]:
                s, f, t= errhand.get_status(s, 100, f, "PAN Already registered", t, "no")

        if rec['sinuparn'] != '':                
            if rec['sinuparn'] == pyld["sinuparn"]:
                s, f, t= errhand.get_status(s, 100, f, "ARN Already registered", t, "no")

        if rec['sinupmobile'] != '':
            if rec['sinupmobile'] == pyld["sinupmobile"]:
                s, f, t= errhand.get_status(s, 100, f, "Mobile Already registered", t, "no")
        
        if s > 0: #incase one of the above already exists
            if rec["usercusttype"] == pyld["usercusttype"]:
                s, f, t= errhand.get_status(s, 100, f, "Userid Already exists with same Adhaar/PAN/ARN/MOBILE for selected cust type (ie...Resigter as)", t, "yes")
                stat = "fail"


'''



@bp_login.route("/kycupdate",methods=["GET","POST","OPTIONS"])
def kycupdate():
    if request.method=="OPTIONS":
        print("inside kycupdate options")
        response1 = make_response(jsonify("inside signup options"),200)
        #response1.headers['Access-Control-Allow-Headers'] = "Origin, entityid, Content-Type, X-Auth-Token, countryid"
        #response1.headers.add("Access-Control-Allow-Headers", "Origin, entityid, Content-Type, X-Auth-Token, countryid")
        return response1

    elif request.method=="POST":
        print("inside kycupdate POST")
        s = 0
        f = None
        t = None #message to front end
        payload = request.get_json()
        print(payload)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        print(s)
        status, kyc_data = kyc_detail_update(payload)
        print(kyc_data)

        if status == "success":
            resp = make_response(jsonify(status), 200)
        else:
            resp = make_response(jsonify(status), 400)
        return resp

def kyc_detail_update(pan_data):
        s = 0
        f = None
        t = None #message to front end

        userid =   pan_data["userid"]
        entityid = pan_data["entityid"]
        cntryid = pan_data["cntryid"]
        pan = pan_data["pan"]
        kyc = "N"
        username = ''
        print(pan_data)
        print(pan)
        if pan != '' or pan != None:
            pan_payload = {'pan': pan}
        else:
            pan_payload = None

        #Get PAN validated and the PAN data
        if pan_payload != None:
            try:
                r = requests.post(configs.PANVALURL[configs.LIVE], data=json.dumps(pan_payload))
            except requests.exceptions.Timeout:
                print("timeout exception with panvalidation")
                pan_data = {"pan_name": None, "kyc_status": None}
            except requests.exceptions.RequestException as e:
                print("exception with panvalidation")
                print(e)
                pan_data = {"pan_name": None, "kyc_status": None}
            else:
                pan_data = json.loads(r.content)
                print(json.loads(r.content))

            if pan_data["pan_name"] != None:
                username = pan_data["pan_name"]
            else:
                username = ''            
            if pan_data["kyc_status"] == "KYC Registered-New KYC":
                kyc = "Y"
        else:
            username = ''
            kyc = "N"
        
        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None

        if s <= 0:
            s1, f1 = db.mydbbegin(con, cur)
            print(s1,f1)

            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

        if s <= 0:
            command = cur.mogrify("""
                        UPDATE ncusr.userlogin SET username = %s, kyc_compliant = %s, userstatlstupdt = CURRENT_TIMESTAMP, lmtime = CURRENT_TIMESTAMP 
                        WHERE userid = %s AND entityid = %s AND countryid = %s;
                        """,(username, kyc, userid, entityid, cntryid,))
            print(command)
            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s > 0:
                s, f, t= errhand.get_status(s, 200, f, "KYC userlogin table update failed", t, "no")
            print('KYC ncusr.userlogin update is successful')

            command = cur.mogrify("""
                        UPDATE ncusr.userdetails SET userkycstatus = %s, lmtime = CURRENT_TIMESTAMP 
                        WHERE userid = %s AND sinuppan = %s AND entityid = %s AND countryid = %s;
                        """,(kyc, userid, pan, entityid, cntryid,))
            print(command)
            cur, s1, f1 = db.mydbfunc(con,cur,command)
            s, f, t= errhand.get_status(s, s1, f, f1, t, "no")
            s1, f1 = 0, None

            if s > 0:
                s, f, t= errhand.get_status(s, 200, f, "KYC userdetails table update failed", t, "no")
            print('KYC ncusr.userdetails update is successful')
        print (s)
        if s <= 0:
            con.commit()
            print("after commit")
            
        
        db.mydbcloseall(con,cur)
        
        if s <= 0:
            kyc_sta = "success"
            kyc_data = {
                "pan": pan,
                "pan_name": username,
                "kyc_status": kyc,
            }
        else:
            kyc_sta = "fail"
            kyc_data = {
                "pan": pan,
                "pan_name": username,
                "kyc_status": kyc,
            }

        return kyc_sta, kyc_data

@bp_login.route("/userregchk",methods=["GET","POST","OPTIONS"])
def userregchk():
    if request.method=="OPTIONS":
        print("inside login options")
        return "inside login options"

    elif request.method=="GET":
        res_to_send, response = userregchk_common(request, 'nc')

        if res_to_send == 'success' or 'fail':
            resps = make_response(jsonify(response), 200)    
            #resps = make_response(jsonify(response), 200 if res_to_send == 'success' else 400)
        else:
            resps = make_response(jsonify(response), 400)
        #dfdfdf
        return resps

def userregchk_common(request, site):
    print("inside login GET")
    s = 0
    f = None
    t = None #message to front end
    response = None
    res_to_send = 'fail'
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    dtkn = jwtf.decodetoken(request, needtkn = False)
    userid = dtkn.get("user_id", None)
    entityid = request.headers.get("entityid", None)
    cntryid = request.headers.get("countryid", None)

    print("iamback")
    print(userid)
    print(entityid)

    if userid == None:
        s, f, t= errhand.get_status(s, 100, f, "No user details sent from client", t, "yes")
    if entityid == None:
        s, f, t= errhand.get_status(s, 100, f, "No entity details sent from client", t, "yes")
    if cntryid == None:
        s, f, t= errhand.get_status(s, 100, f, "No country details sent from client", t, "yes")
    
    if s <= 0:
        con, cur, s1, f1 = db.mydbopncon()
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None

    if s <= 0:
        command = cur.mogrify("""
                                SELECT COUNT(1) FROM ncusr.userlogin WHERE
                                userid = %s AND entityid = %s AND countryid = %s
                                AND userstatus NOT IN ('D') ;
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
            s, f, t = errhand.get_status(s, 200, f, "User data fetch failed with DB error", t, "no")
    print(s,f)

    if s <= 0:
        user_cnt = cur.fetchall()[0][0]
        print(user_cnt)


    if s > 0:
        res_to_send = 'fail'
        response = {
            'uid' : userid,
            'sessionid' : '',
            'status': res_to_send,
            'status_code': s,
            'message': errhand.error_msg_reporting(s, t)
            }
    else:
        if user_cnt > 0:
            res_to_send = 'success'
            response = {
                        'uid' : userid,
                        'sessionid' : None,
                        'status': res_to_send,
                        'status_code': 0,
                        'message': ''
            }
        else:
            s, f, t = errhand.get_status(s, 401, f, "Not a registered user. Signup",t,"yes")
            res_to_send = 'fail'
            response = {
                'uid' : userid,
                'sessionid' : None,
                'status': res_to_send,
                'status_code': s,
                'message': errhand.error_msg_reporting(s, t)
                }

    print(response)
    
    return (res_to_send, response)
    