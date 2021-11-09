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


_ISSUER_URL = "http://"+ DIDSAMPLE.ROLE['issuer']['host'] + ":" + str(DIDSAMPLE.ROLE['issuer']['port'])
_VERIFIER_URL = "http://"+ DIDSAMPLE.ROLE['verifier']['host'] + ":" + str(DIDSAMPLE.ROLE['verifier']['port'])

app = bottle.Bottle()
app.install(canister.Canister())
############## VC Issuance - DRIVER LICENSE ##############

# 0. [POST] Req : Create DID Document
def test_createDIDDocument():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = DIDSAMPLE.ROLE['platform']['urls']['document']
    data = DIDSAMPLE.makeSampleDIDDocument("holder", "Ed25519VerificationKey2018")
    response = requests.post(URL, data=json.dumps(data))
    LOGI("[Holder] Create DID Document : %s, VC Data : %s" % (data['id'], data))
    if response.status_code >= 500 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
        
# 1.[GET] Req : locations
def test_getURLs():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _ISSUER_URL+'/urls' 
    response = requests.get(URL) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] 위치 : %s : %s" % (response.status_code, response.text))
    data = json.loads(response.text)
    assert True

# 2.[POST] Req : DID Auth
def test_DID_Auth():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['didAuth'] 
    data = {'did': DIDSAMPLE.ROLE['holder']['did']}
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
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True

# 4.[GET] Req : VC
def test_reqVC():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL =  _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getCredentialProposal']
    _data = {
        'did': DIDSAMPLE.ROLE['holder']['did'], 
        'schemaID':"schemaID1",
        'creDefId':"credentialDefinitionID1"
    } 
    response = requests.get(URL, params=(data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VC 발급 결과 : %s" % response.text)
    VC_driverLicense = json.loads(response.text)['VC']
    assert True

def test_ackMessage(platform_url):
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getAckMessage']
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)

############## VC Issuance - PROTOCON PASS ##############
# 
# 0.[POST] req : Buy Protoconpass
def test_buyProtoconpass():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['postBuyProtoconPass']
    data = {'buyInfo': {"DID":"TEST", "CreditCard":"TEST"}}
    response = requests.post(URL, data=json.dumps(data))
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    data = json.loads(response.text)
    buyID = data['buyID']
    assert True

# 1.[GET] Req : Locations
def test_getURLs2():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _ISSUER_URL+'/urls' 
    response = requests.get(URL) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] 위치 : %s : %s" % (response.status_code, response.text))
    data = json.loads(response.text)
    assert True

# 2.[POST] Req : DID Auth
def test_DID_Auth2():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['didAuth'] 
    data = {'did': DIDSAMPLE.ROLE['holder']['did']}
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
def test_ChallengeResponse2():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True

# 4.[GET] Req : VC
def test_reqVC2():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL =  _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getCredentialProposal']
    _data = {
        'did': DIDSAMPLE.ROLE['holder']['did'], 
        'schemaID':"schemaID2",
        'creDefId':"credentialDefinitionID2"
    } 
    response = requests.get(URL, params=(data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VC 발급 결과 : %s" % response.text)
    VC_protoconPass = json.loads(response.text)['VC']
    assert True

def test_ackMessage2(platform_url, myJWT):
    URL = platform_url + DIDSAMPLE.ROLE["issuer"]['urls']['getAckMessage']
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)

############## VP - PROTOCON PASS, DRIVER LICENSE ##############
# 
# 1.[GET] Req : locations
def test_getURLs():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _VERIFIER_URL+'/urls' 
    response = requests.get(URL) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] 위치 : %s : %s" % (response.status_code, response.text))
    data = json.loads(response.text)
    assert True

# 2.[POST] Req : DID Auth
def test_DID_Auth():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _VERIFIER_URL + DIDSAMPLE.ROLE["verifier"]['urls']['didAuth'] 
    data = {'did': DIDSAMPLE.ROLE['holder']['did']}
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
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True





# 2.[POST] Req : DID & VP
def test_DID_VP():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    vcArr = [VC_driverLicense, VC_protoconPass]
    holderDID = DIDSAMPLE.ROLE['holder']['did']
    vp = DIDSAMPLE.makeSampleVPwithoutJWS(holderDID, vcArr)
    vpJWS = DID.makeJWS_jwtlib(vp, DIDSAMPLE.ROLE['holder']['privateKey'])
    vp['proof'][0]["jws"] = vpJWS
    URL = _VERIFIER_URL
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
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True

# 4.[GET] Req : VP
def test_VPGet():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = VPGet
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VP 결과 : %s" % response.text)
    assert True
    
