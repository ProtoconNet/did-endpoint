# -*- coding: utf-8 -*-
import bottle
import canister
import json
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
LOG = DIDLOG.__get_logger('info', 'holder.log')
LOGI = LOG.info
LOGD = LOG.debug
LOGW = LOG.warning
LOGE = LOG.error

_url = "http://"+ DIDSAMPLE.ROLE['issuer']['host'] + ":" + str(DIDSAMPLE.ROLE['issuer']['port'])

app = bottle.Bottle()
app.install(canister.Canister())
############## VC Issuance - DRIVER LICENSE ##############

# 0. [POST] Req : Create DID Document
URL = DIDSAMPLE.ROLE['platform']['urls']['document']

data = DIDSAMPLE.makeSampleDIDDocument("holder", "Ed25519VerificationKey2018")
response = requests.post(URL, data=json.dumps(data))
LOGI("[Holder] Create DID Document : %s, VC Data : %s" % (data['id'], data))

# 1.[GET] Req : VC Schema location
URL = _url+'/VCSchema?schema=driverLicense' 
response = requests.get(URL) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] VC Schema 위치 : %s : %s" % (response.status_code, response.text))
data = json.loads(response.text)
VCGet = data['VCGet']
VCPost = data['VCPost']

# 2.[POST] Req : DID & VC
URL = VCPost
data = {'did': DIDSAMPLE.ROLE['holder']['did'],
'credentialSubject':DIDSAMPLE.ROLE['holder']['credentialSubject']['driverLicense']} 
response = requests.post(URL, data=json.dumps(data))
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
myJWT = response.headers.get('Authorization')
LOGI("[Holder] DID : %s, VC Data : %s, JWT : %s" % (data['did'], data, myJWT))

data = json.loads(response.text)
signature = DID.signString(data['payload'], DIDSAMPLE.ROLE['holder']['privateKey'])

# 3.[GET] Req : Challenge & Response 
URL = data['endPoint'] + '?signature='+signature 
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] DID Auth 결과 : %s" % response.text)

# 4.[GET] Req : VC
URL = VCGet
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] VC 발급 결과 : %s" % response.text)
VC_driverLicense = json.loads(response.text)['VC']

############## VC Issuance - JEJU PASS ##############
# 
# 0.[POST] req : Buy Jejupass
URL = _url+'/jejuPass' 
data = {'did': DIDSAMPLE.ROLE['holder']['did'],
'credentialSubject':DIDSAMPLE.ROLE['holder']['credentialSubject']['jejuPass']} 
response = requests.post(URL, data=json.dumps(data))
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
data = json.loads(response.text)
buyID = data['buyID']

# 1.[GET] Req : VC Schema location - jejuPass
URL = _url+'/VCSchema?schema=jejuPass' 
response = requests.get(URL) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] VC Schema 위치 : %s : %s" % (response.status_code, response.text))
data = json.loads(response.text)
VCGet = data['VCGet']
VCPost = data['VCPost']

# 2.[POST] Req : DID & VC
URL = VCPost
data = {'did':DIDSAMPLE.ROLE['holder']['did'], 'credentialSubject':{"buyID":buyID}}
response = requests.post(URL, data=json.dumps(data))
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
myJWT = response.headers.get('Authorization')
LOGI("[Holder] JWT : %s" % (myJWT))

data = json.loads(response.text)
signature = DID.signString(data['payload'], DIDSAMPLE.ROLE['holder']['privateKey'])

# 3.[GET] Req : Challenge & Response 
URL = data['endPoint'] + '?signature='+signature 
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] DID Auth 결과 : %s" % response.text)

# 4.[GET] Req : VC
URL = VCGet
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] VC 발급 결과 : %s" % response.text)
VC_jejuPass = json.loads(response.text)['VC']

############## VP - JEJU PASS, DRIVER LICENSE ##############
# 

_url = "http://"+ DIDSAMPLE.ROLE['verifier']['host'] + ":" + str(DIDSAMPLE.ROLE['verifier']['port'])

# 1.[GET] Req : VP Schema location
URL = _url+'/VPSchema?schema=rentCar' 
response = requests.get(URL) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] VP : %s : %s" % (response.status_code, response.text))
data = json.loads(response.text)
VPGet = data['VPGet']
VPPost = data['VPPost']

# 2.[POST] Req : DID & VP
vcArr = [VC_driverLicense, VC_jejuPass]
holderDID = DIDSAMPLE.ROLE['holder']['did']
vp = DIDSAMPLE.makeSampleVPwithoutJWS(holderDID, vcArr)
vpJWS = DID.makeJWS_jwtlib(vp, DIDSAMPLE.ROLE['holder']['privateKey'])
vp['proof'][0]["jws"] = vpJWS

URL = VPPost
data = {'did': DIDSAMPLE.ROLE['holder']['did'], 'vp':vp} 
response = requests.post(URL, data=json.dumps(data))
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
myJWT = response.headers.get('Authorization')
LOGI("[Holder] DID : %s, VP Data : %s, JWT : %s" % (data['did'], data, myJWT))

data = json.loads(response.text)
signature = DID.signString(data['payload'], DIDSAMPLE.ROLE['holder']['privateKey'])

# 3.[GET] Req : Challenge & Response 
URL = data['endPoint'] + '?signature='+signature 
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] DID Auth 결과 : %s" % response.text)

# 4.[GET] Req : VP
URL = VPGet
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
if response.status_code >= 400 :
    LOGE("ERROR : %s" % response.status_code)
LOGI("[Holder] VP 결과 : %s" % response.text)
