from datetime import datetime

from assetscube.common import dbfunc as db
from assetscube.common import error_logics as errhand

import jwt
import requests
import json
      
def decodetoken(request, needtkn = False):
    print('inside decodetoken',request.headers)
    if 'Authorization' in request.headers:
        print('inside aut')
        token_full = request.headers.get('Authorization')
        if token_full.startswith("Bearer "):
            token =  token_full[7:]
            
        print(token)
        natjwtdecoded = jwt.decode(token, verify=False)      
        print(natjwtdecoded)  
        userid = natjwtdecoded['user_id']
        entityid = natjwtdecoded.get('entityid','')
        cntryid =  natjwtdecoded.get('countryid','')
        print('getting value')
        print(userid, entityid, cntryid)
        #entityid=natjwtdecoded['entityid']
        if  (not userid) or (userid ==""):
            status = 'failed'

        if needtkn:
            if token:
                return token, natjwtdecoded
            else:
                return None * 2
        else:
            return natjwtdecoded

def generatejwt(d):
    #Create JWT
    print("inside jwt creation function")
    s = 0
    f = None
    t = None #message to front end
    response = None
    res_to_send = 'fail'
    print(d)
    con, cur, s1, f1 = db.mydbopncon()
    s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
    s1, f1 = 0, None
    print("DB connection established", s,f,t)
    
    natseckey = "secret"
    
    if s <= 0:
        command = cur.mogrify("""
                                SELECT json_agg(a) FROM (
                                SELECT secretcode,seccdid FROM ncapp.secrettkn 
                                WHERE entityid = %s AND countryid =%s
                                ) as a
                            """,(d["ei"], d["ci"]))
        print(command)

        cur, s1, f1 = db.mydbfunc(con,cur,command)
        s, f, t = errhand.get_status(s, s1, f, f1, t, "no")
        s1, f1 = 0, None
        print('----------------')
        print(s)
        print(f)
        print('----------------')
        if s > 0:
            s, f, t = errhand.get_status(s, 200, f, "secret fetch failed with DB error", t, "no")
    print(s,f)
    
    db_rec = None
    if s <= 0:
        db_rec = cur.fetchall()[0][0]
        
    
        if len(db_rec) < 1:
            s, f, t= errhand.get_status(s, 100, f, "Unable to get secret", t, "no")            
        else:
            print(db_rec)
            db_rec = db_rec[0]
            print("got the secret string successfully")
            pass            
    
    print(s,f)

    if s <= 0:
        secretcode = db_rec.get("secretcode", None)
        if secretcode == None:
            s, f, t = errhand.get_status(s, 200, f, "unable to get secret code", t, "no")

        seccdid = db_rec.get("seccdid", None)
        if seccdid == None:
            s, f, t = errhand.get_status(s, 200, f, "unable to get secret code id", t, "no")
    print("@@@@@@@@@@@@@")
    print(secretcode)
    print("@@@@@@@@@@@@@")
    if s <= 0:
        #Call JWT to generate JWT START
        natjwt =  jwt.encode(
                            { 
                              "iss": "ncj",
                              "exp": d["exp"],
                              "iat": datetime.now().strftime('%d%m%Y%H%M%S%f'),                            
                              "passtkn": d["passtkn"],
                              "skd": seccdid,
                              "eid": d["ei"], 
                              "cid": d["ci"],
                              "ncuserid": d["ncuserid"]
                            }, 
                            secretcode, 
                            algorithm='HS256')          
    print("printing nat jwt")
    print(natjwt)
    #Call JWT to generate JWT END
    db.mydbcloseall(con,cur)
    return (json.dumps({"ncjwt" :natjwt.decode("utf-8")}))

def verify_ncj_tkn(request):
    print('inside verify_ncj_tkn',request.headers)
    if 'Authorization' in request.headers:
        print('inside aut')
        token_full = request.headers.get('Authorization')
        if token_full.startswith("Bearer "):
            token =  token_full[7:]
            
        print(token)
        natjwtdecoded = jwt.decode(token, verify=False)      
        print(natjwtdecoded)  
        
        '''
        get seccid
        get seccode from db based on seccid, eid and cid
        validate the jwt based on the seccode
        '''
                
        userid = natjwtdecoded['user_id']
        entityid = natjwtdecoded.get('entityid','')
        cntryid =  natjwtdecoded.get('countryid','')
        print('getting value')
        print(userid, entityid, cntryid)
        #entityid=natjwtdecoded['entityid']
        if  (not userid) or (userid ==""):
            status = 'failed'

        if needtkn:
            if token:
                return token, userid, entityid, cntryid
            else:
                return None * 3
        else:
            return userid