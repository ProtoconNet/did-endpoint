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
def test_createDIDDocument():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = DIDSAMPLE.ROLE['platform']['urls']['document']
    data = DIDSAMPLE.makeSampleDIDDocument("holder", "Ed25519VerificationKey2018")
    response = requests.post(URL, data=json.dumps(data))
    LOGI("[Holder] Create DID Document : %s, VC Data : %s" % (data['id'], data))
    if response.status_code >= 500 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
        
# 1.[GET] Req : VC Schema location
def test_getDriverLicense():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = _url+'/VCSchema?schema=driverLicense' 
    response = requests.get(URL) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VC Schema 위치 : %s : %s" % (response.status_code, response.text))
    data = json.loads(response.text)
    VCGet = data['VCGet']
    VCPost = data['VCPost']
    assert True

# 2.[POST] Req : DID & VC
def test_DID_VC1():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = VCPost
    data = {'did': DIDSAMPLE.ROLE['holder']['did'],
    'credentialSubject':{'driver’s license':''}} 
    response = requests.post(URL, data=json.dumps(data))
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    myJWT = response.headers.get('Authorization')
    LOGI("[Holder] DID : %s, VC Data : %s, JWT : %s" % (data['did'], data, myJWT))
    data = json.loads(response.text)
    signature = DID.signString(data['payload'], DIDSAMPLE.ROLE['holder']['privateKey'])
    assert True

# 3.[GET] Req : Challenge & Response 
def test_ChallengeResponse():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True

# 4.[GET] Req : VC
def test_reqVC():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = VCGet
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VC 발급 결과 : %s" % response.text)
    VC_driverLicense = json.loads(response.text)['VC']
    assert True

############## VC Issuance - JEJU PASS ##############
# 
# 0.[POST] req : Buy Jejupass
def test_buyJejupass():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = _url+'/jejuPass' 
    data = {'did': DIDSAMPLE.ROLE['holder']['did'],
    'credentialSubject':DIDSAMPLE.ROLE['holder']['credentialSubject']['jejuPass']} 
    response = requests.post(URL, data=json.dumps(data))
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    data = json.loads(response.text)
    buyID = data['buyID']
    assert True

# 1.[GET] Req : VC Schema location - jejuPass
def test_getVCSchemaLocation():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = _url+'/VCSchema?schema=jejuPass' 
    response = requests.get(URL) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VC Schema 위치 : %s : %s" % (response.status_code, response.text))
    data = json.loads(response.text)
    VCGet = data['VCGet']
    VCPost = data['VCPost']
    assert True

# 2.[POST] Req : DID & VC
def test_getDID_VC():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = VCPost
    data = {'did':DIDSAMPLE.ROLE['holder']['did'], 'credentialSubject':{"buyID":buyID}}
    response = requests.post(URL, data=json.dumps(data))
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    myJWT = response.headers.get('Authorization')
    LOGI("[Holder] JWT : %s" % (myJWT))
    data = json.loads(response.text)
    signature = DID.signString(data['payload'], DIDSAMPLE.ROLE['holder']['privateKey'])
    assert True

# 3.[GET] Req : Challenge & Response 
def test_challenge_response_():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True

# 4.[GET] Req : VC
def test_GET_VC_():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = VCGet
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VC 발급 결과 : %s" % response.text)
    VC_jejuPass = json.loads(response.text)['VC']
    assert True

############## VP - JEJU PASS, DRIVER LICENSE ##############
# 
def test_VP():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    _url = "http://"+ DIDSAMPLE.ROLE['verifier']['host'] + ":" + str(DIDSAMPLE.ROLE['verifier']['port'])
    # 1.[GET] Req : VP Schema location
    URL = _url+'/VPSchema?schema=rentCar' 
    response = requests.get(URL) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VP : %s : %s" % (response.status_code, response.text))
    data = json.loads(response.text)
    VPGet = data['VPGet']
    VPPost = data['VPPost']
    assert True

# 2.[POST] Req : DID & VP
def test_DID_VP():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
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
        assert False
    myJWT = response.headers.get('Authorization')
    LOGI("[Holder] DID : %s, VP Data : %s, JWT : %s" % (data['did'], data, myJWT))

    data = json.loads(response.text)
    signature = DID.signString(data['payload'], DIDSAMPLE.ROLE['holder']['privateKey'])
    assert True

# 3.[GET] Req : Challenge & Response 
def test_challenge_response_VP():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True

# 4.[GET] Req : VP
def test_VPGet():
    global signature, myJWT, data, VCGet, VCPost, VC_driverLicense, VC_jejuPass, buyID, VPGet, VPPost
    URL = VPGet
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VP 결과 : %s" % response.text)
    assert True
    
