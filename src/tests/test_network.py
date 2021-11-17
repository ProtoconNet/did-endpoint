# -*- coding: utf-8 -*-
from datetime import datetime
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

# 0-1. [POST] Req : Get DID Document
def test_getDIDDocument():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    documentURL = DIDSAMPLE.getDIDDocumentURL(DIDSAMPLE.ROLE['holder']['did'])
    pubkey = DID.getPubkeyFromDIDDocument(documentURL)
    if pubkey == None:
        assert False
    assert True

# 0-2. [POST] Req : Create Schema
def test_createSchema():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass, schemaID
    try:
        schemaName = DIDSAMPLE._SCHEMA['schemaID1']['schemaName']
        version = DIDSAMPLE._SCHEMA['schemaID1']['version']
        attribute = DIDSAMPLE._SCHEMA['schemaID1']['attribute']
        URL = DIDSAMPLE.ROLE['platform']['urls']['createSchema']
        dt = {"schemaName" : schemaName, "version" : version, "attribute" : attribute}
        response = requests.post(URL, data=json.dumps(dt))
        text = json.loads(response.text)
        schemaID = text["id"]
        if response.status_code >= 400 :
            LOGE("ERROR : %s" % response.status_code)
            assert False        
        assert True    
    except Exception as ex:
        assert False

# 0-3. [POST] Req : Create Definition
def test_createDefinition():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass, schemaID
    try:
        tag = "schemaID1", 
        revocation = False
        URL = DIDSAMPLE.ROLE['platform']['urls']['createDefinition']
        dt = {"schemaID" : schemaID, "tag" : tag, "revocation" : revocation}
        response = requests.post(URL, data=json.dumps(dt))
        if response.status_code >= 400 :
            LOGE("ERROR : %s" % response.status_code)
            assert False        
        assert True    
    except Exception as ex:
        assert False

# 1.[GET] Req : locations
def test_VC_getURLs_driverLicense():
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
def test_VC_DID_Auth_driverLicense():
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
def test_VC_ChallengeResponse_driverLicense():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True

# 4.[GET] Req : VC
def test_VC_getCredentialProposal_driverLicense():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL =  _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getCredentialProposal']
    _data = {
        'did': DIDSAMPLE.ROLE['holder']['did'], 
        'schemaID':"schemaID1",
        'creDefId':"credentialDefinitionID1"
    } 
    response = requests.get(URL, params=(_data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    preview = json.loads(response.text)['credentialAttributeValueList']
    LOGI("[Holder] VC 발급 Preview (Need Confirm): %s" % preview)
    assert True

# 5.[GET] Confirm : VC
def test_VC_confirmAndgetCredentialRequest_driverLicense():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL =  _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getCredentialRequest']
    _data = {
        'did': DIDSAMPLE.ROLE['holder']['did'], 
        'schemaID':"schemaID1",
        'creDefId':"credentialDefinitionID1"
    } 
    response = requests.get(URL, params=(_data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VC 발급 결과 : %s" % response.text)
    VC_driverLicense = json.loads(response.text)['VC']
    print(response.text)
    assert True

def test_VC_ackMessage_driverLicense():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getAckMessage']
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)

############## VC Issuance - PROTOCON PASS ##############
# 
# 0.[POST] req : Buy Protoconpass
def test_VC_buyProtoconpass():
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
def test_VC_getURLs_protoconPass():
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
def test_VC_DID_Auth_protoconPass():
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
def test_VC_ChallengeResponse_protoconPass():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True

# 4.[GET] Req : VC
def test_VC_getCredentialProposal_protoconPass():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL =  _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getCredentialProposal']
    _data = {
        'did': DIDSAMPLE.ROLE['holder']['did'], 
        'schemaID':"schemaID2",
        'creDefId':"credentialDefinitionID2"
    } 
    response = requests.get(URL, params=(_data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    preview = json.loads(response.text)['credentialAttributeValueList']
    LOGI("[Holder] VC 발급 Preview (Need Confirm): %s" % preview)
    assert True

# 5.[GET] Confirm : VC
def test_VC_confirmAndgetCredentialRequest_protoconPass():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL =  _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getCredentialRequest']
    _data = {
        'did': DIDSAMPLE.ROLE['holder']['did'], 
        'schemaID':"schemaID2",
        'creDefId':"credentialDefinitionID2"
    } 
    response = requests.get(URL, params=(_data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] VC 발급 결과 : %s" % response.text)
    VC_protoconPass = json.loads(response.text)['VC']
    assert True

def test_VC_ackMessage_protoconPass():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getAckMessage']
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)

############## VP - PROTOCON PASS, DRIVER LICENSE ##############
# 
# 1.[GET] Req : locations
def test_VP_getURLs():
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
def test_VP_DID_Auth():
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
def test_VP_ChallengeResponse():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID Auth 결과 : %s" % response.text)
    assert True


def test_VP_presentationProposal():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    URL = _VERIFIER_URL + DIDSAMPLE.ROLE["verifier"]['urls']['getPresentationProposal']
    holderDID = { 'did' : DIDSAMPLE.ROLE['holder']['did'] }
    response = requests.get(URL, params=holderDID)
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] DID : %s, Presentations : %s, JWT : %s" % (holderDID, response.text, myJWT))
    assert True

# 2.[POST] Req : DID & VP
def test_VP_postPresentationProof():
    global signature, myJWT, data, VC_driverLicense, VC_protoconPass
    vcArr = [VC_driverLicense, VC_protoconPass]
    holderDID = DIDSAMPLE.ROLE['holder']['did']
    vp = DIDSAMPLE.makeSampleVPwithoutJWS(holderDID, vcArr)
    vpJWS = DID.makeJWS_jwtlib(vp, DIDSAMPLE.ROLE['holder']['privateKey'])
    vp['proof'][0]["jws"] = vpJWS
    URL = _VERIFIER_URL + DIDSAMPLE.ROLE["verifier"]['urls']['postPresentationProof']
    data = {'did': DIDSAMPLE.ROLE['holder']['did'], 'vp':vp} 
    response = requests.post(URL, data=json.dumps(data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
        assert False
    LOGI("[Holder] RESULT OF VP VERIFICATION: %s" % response.text)
    assert True
