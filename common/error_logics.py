def get_status(curstatus,newstatus,curreason, newreason, usermsg, addtousermsg = "no"):
    '''
    status =   
                -300 --> success
                -100 --> warning for which program flow not to be stopped
                0 --> empty
                100  --> data error
                    101 --> user already registered
                200  --> db error
                300  --> both data and db error
                400 --> User related errors
                    401 --> User already have active session
    '''
    print('get_status start')
    print('curstatus',curstatus)
    print('newstatus',newstatus)
    print('curreason',curreason)
    print('newreason',newreason )
    if curstatus == None:
        curstatus = 0

    setstatus = 0
    
    if newstatus == -300:
        setstatus = -300
        setreason = None
    else:
        if curstatus <= 0:
            setstatus = newstatus
        elif curstatus < 300:            
            setstatus = 300
        elif curstatus > 300:
            setstatus = newstatus
        elif curstatus == 300:
            setstatus = 300

        if curreason != None:
            if newreason != None:
                setreason = curreason + " | " + newreason
            else:
                setreason = curreason
        else:
            if newreason != None:
                setreason = newreason
            else:
                setreason = None

    if addtousermsg == "yes":
        if usermsg  != None:
            if newreason != None:
                usermsg = usermsg + " | " + newreason
            else:
                usermsg = usermsg
        else:
            if newreason != None:
                usermsg = newreason
            else:
                usermsg = None
    else:
        usermsg = usermsg
    
    
    print('get_status end')
    print('curstatus',curstatus)
    print('newstatus',newstatus)
    print('curreason',curreason)
    print('newreason',newreason )

    return 0 if setstatus == None else setstatus, setreason, usermsg


def front_end_msg(t):
    if t:
        t = t + " | " + t

def error_msg_reporting(s, t):
    print('error_msg_reporting start')
    if s > 200:
        client_error_msg = t if t else '' + "\n[server]Multiple system error.  Please contact Support"
    elif s == 100:
        client_error_msg = t if t else '' + "\n[server]Looks like a Data error.  Please contact Support"
    elif s == 200:
        client_error_msg = t if t else '' +  "\n[server]Oops...! Data base (Technical) error occured.  Please contact Support"
    else:
        client_error_msg = None
    
    print("log message to debug")
    print('@@@@@@@@@@@@@@@@@@@@@@@@@')
    print(s)
    print(t)
    print(client_error_msg)
    print('@@@@@@@@@@@@@@@@@@@@@@@@@')
    print('error_msg_reporting end')
    return client_error_msg



def get_status1(curstatus,newstatus,curreason, newreason, usermsg, addtousermsg = "no"):
    '''
    status =   
                -300 --> success
                -100 --> warning for which program flow not to be stopped
                0 --> empty
                100  --> data error
                    101 --> user already registered
                200  --> db error
                300  --> both data and db error
                400 --> User related errors
                    401 --> User already have active session
    '''
    print('get_status start')
    print('curstatus',curstatus)
    print('newstatus',newstatus)
    print('curreason',curreason)
    print('newreason',newreason )
    if curstatus == None:
        curstatus = [0]

    setstatus = 0
    
    if newstatus == -300:
        setstatus = -300
        setreason = None
    else:
        if curstatus <= 0:
            setstatus = newstatus
        elif curstatus < 300:            
            setstatus = 300
        elif curstatus > 300:
            setstatus = newstatus
        elif curstatus == 300:
            setstatus = 300

        if curreason != None:
            if newreason != None:
                setreason = curreason + " | " + newreason
            else:
                setreason = curreason
        else:
            if newreason != None:
                setreason = newreason
            else:
                setreason = None

    if addtousermsg == "yes":
        if usermsg  != None:
            if newreason != None:
                usermsg = usermsg + " | " + newreason
            else:
                usermsg = usermsg
        else:
            if newreason != None:
                usermsg = newreason
            else:
                usermsg = None
    else:
        usermsg = usermsg
    
    
    print('get_status end')
    print('curstatus',curstatus)
    print('newstatus',newstatus)
    print('curreason',curreason)
    print('newreason',newreason )

    return 0 if setstatus == None else setstatus, setreason, usermsg