# -*- coding: utf-8 -*-
import bottle
import canister
import json
from ed25519.keys import SigningKey
import requests
from bottle import response
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from tools import did as DID
from tools import log as DIDLOG
from configs import samples as DIDSAMPLE

# try :
#     # Monitoring :
#     from configs import privates as DIDPRIVATE
#     DIDLOG.init(DIDPRIVATE.LOG['sentryURL'])
# except Exception:
#     print('Not exist : configs/privates. LOG={"sentryURL" : "..."}')


# JUST Logging
LOG = DIDLOG.__get_logger('info')
LOGI = LOG.info
LOGD = LOG.debug
LOGW = LOG.warning

_url = "http://"+ DIDSAMPLE.ROLE['issuer']['host'] + ":" + str(DIDSAMPLE.ROLE['issuer']['port'])

app = bottle.Bottle()
app.install(canister.Canister())

# 0. [POST] Req : Create DID Document
URL = DIDSAMPLE.ROLE['platform']['urls']['document']
data = DIDSAMPLE.makeSampleDIDDocument()
response = requests.post(URL, data=json.dumps(data))
LOGI("[Holder] Create DID Document : %s, VC Data : %s" % (data['id'], data))


# 1.[GET] Req : VC Scheme location
URL = _url+'/VCScheme?scheme=driverLicense' 
response = requests.get(URL) 
LOGI("[Holder] VC Claim 위치 : %s : %s" % (response.status_code, response.text))
data = json.loads(response.text)
VCGet = data['VCGet']
VCPost = data['VCPost']

# 2.[POST] Req : DID & VC
URL = VCPost
data = {'did': DIDSAMPLE.ROLE['holder']['did'],
'credentialSubject':DIDSAMPLE.ROLE['holder']['credentialSubject']} 
response = requests.post(URL, data=json.dumps(data))
myJWT = response.headers.get('Authorization')
LOGI("[Holder] DID : %s, VC Data : %s, JWT : %s" % (data['did'], data, myJWT))

#assert(jwt.decode(myJWT, "abc", algorithms=["HS256"]))
data = json.loads(response.text)
signature = DID.signString(data['payload'], DIDSAMPLE.ROLE['holder']['privateKey'])

# 3.[GET] Req : Challenge & Response 
URL = data['endPoint'] + '?signature='+signature 
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
LOGI("[Holder] DID Auth 결과 : %s" % response.text)

# 4.[GET] Req : VC
URL = VCGet
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
LOGI("[Holder] VC 발급 결과 : %s" % response.text)
