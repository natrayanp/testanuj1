# LIVE = 0
# UAT = 1
LIVE = 1

SIGNUPURL = ["https://nawalcube.com/login/signup","http://localhost:4200/login/signup"]
LOGINURL = ["https://nawalcube.com/authorise/auth","http://localhost:4200/authorise/auth"]
PANVALURL = ["","http://localhost:8082/panvali"]

INSTALLDATA = [
    {
    "entityid": "NAWALCUBE",
    "countryid": "IN"
},
{
    "entityid": "NAWALCUBE",
    "countryid": "IN"
}]

# gunicorn --reload --bind=127.0.0.1:8080 nawalcube_server:app