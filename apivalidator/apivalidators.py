from . import bp_apivali
from flask import redirect, request,make_response, jsonify
from datetime import datetime
from nawalcube.common import jwtfuncs as jwtf
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from nawalcube_server.common import serviceAccountKey as sak

@bp_apivali.route('/apiaccessvali',methods=['GET','POST','OPTIONS'])
def apiaccessvali():

    print("inside apiaccessvali")    
    print("inside signup")
    token = None
    session_id = None
    path = request.path

    token, userid, entityid = jwtf.decodetoken(request, needtkn = True)
    
    if 'mysession' in request.headers:
        print('inside mysession')
        session_id = request.headers.get('mysession')
        
    statu = apivalidation_controller(session_id = session_id, token = token, path = path)

    return statu



def apivalidation_controller(session_id = None, token = None, path = None):    

    if path == '/singup':
        ses_val_status = True
        fb_val_status = True
    else:
        if session_id == None:
            ses_val_status = False
        else:
            ses_val_status, f = apiaccessvali_session(session_id)        

        if token == None:
            fb_val_status = False
        else:
            fb_val_status, f = apiaccessvali_firebase(token)

    return True if (ses_val_status and fb_val_status) else False


def apiaccessvali_session(session_id):
    return True, None


def apiaccessvali_firebase(token):
    print("inside firebase validation")
    
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    #firebase auth setup
    #cred = credentials.Certificate('/home/natrayan/project/AwsProject/Python/nawalcubebackend/nawalcube/authentication/serviceAccountKey.json')
    cred = credentials.Certificate(sa.SERVICEAC)
    default_app = firebase_admin.initialize_app(cred)

    try:
        decoded_token = auth.verify_id_token(token)
    except ValueError:
        status = False
        failreason = 'Not a valid user credentials'
    else:
        status = True
        failreason = ''

    return status, failreason