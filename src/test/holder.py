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

def createDIDDocument():
    # 0. [POST] Req : Create DID Document
    URL = DIDSAMPLE.ROLE['platform']['urls']['document']
    data = DIDSAMPLE.makeSampleDIDDocument("holder", "Ed25519VerificationKey2018")
    response = requests.post(URL, data=json.dumps(data))
    LOGI("[Holder] Create DID Document : %s, VC Data : %s" % (data['id'], data))

def didAuth(platform_url):
    #1 DID AUTH 0 - sending DID
    URL = platform_url + DIDSAMPLE.ROLE["issuer"]['urls']['getDIDAuth']
    data = {'did': DIDSAMPLE.ROLE['holder']['did']} 
    response = requests.post(URL, data=json.dumps(data))
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
    myJWT = response.headers.get('Authorization')
    LOGI("[Holder] DID : %s, JWT : %s" % (data['did'], myJWT))

    data = json.loads(response.text)
    signature = DID.signString(data['payload'], DIDSAMPLE.ROLE['holder']['privateKey'])

    #2 DID AUTH 1 - Sending signedPayload
    URL = data['endPoint'] + '?signature='+signature 
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
    LOGI("[Holder] RESULT OF DID Auth : %s" % response.text)
    return myJWT


def getVC(myJWT, did, schemaID, credentialDefinitionID):
    URL = _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getCredentialProposal']
    data = {
        'did': did,
        'schemaID':schemaID,
        'creDefId':credentialDefinitionID
        } 
    response = requests.get(URL, params=(data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
    preview = json.loads(response.text)['credentialAttributeValueList']
    LOGI("[Holder] PREVIEW - VC : %s" % response.text)

    ################### NEED USER CONFIRM ##################
    URL = _ISSUER_URL + DIDSAMPLE.ROLE["issuer"]['urls']['getCredentialRequest']
    data = {
        'did': did,
        'schemaID':schemaID,
        'creDefId':credentialDefinitionID
        } 
    response = requests.get(URL, params=(data), headers={'Authorization':'Bearer ' + str(myJWT)})
    vc = json.loads(response.text)['VC']
    return vc

def ackMessage(platform_url, myJWT):
    URL = platform_url + DIDSAMPLE.ROLE["issuer"]['urls']['getAckMessage']
    response = requests.get(URL, headers={'Authorization':'Bearer ' + str(myJWT)}) 
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)


############## VP - JEJU PASS, DRIVER LICENSE ##############

def presentationProposal(myJWT):
    URL = _VERIFIER_URL + DIDSAMPLE.ROLE["verifier"]['urls']['getPresentationProposal']
    holderDID = { 'did' : DIDSAMPLE.ROLE['holder']['did'] }
    response = requests.get(URL, params=holderDID, headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
    #LOGI("[Holder] DID : %s, PresentationRequest : %s, JWT : %s" % (holderDID, response.text, myJWT))
    return response.text

def presentationProof(myJWT, vcArr):
    # 2.[POST] Req : DID & VP
    holderDID = DIDSAMPLE.ROLE['holder']['did']
    vp = DIDSAMPLE.makeSampleVPwithoutJWS(holderDID, vcArr)
    vpJWS = DID.makeJWS_jwtlib(vp, DIDSAMPLE.ROLE['holder']['privateKey'])
    vp['proof'][0]["jws"] = vpJWS
    URL = _VERIFIER_URL + DIDSAMPLE.ROLE["verifier"]['urls']['postPresentationProof']
    data = {'did': DIDSAMPLE.ROLE['holder']['did'], 'vp':vp} 
    response = requests.post(URL, data=json.dumps(data), headers={'Authorization':'Bearer ' + str(myJWT)})
    if response.status_code >= 400 :
        LOGE("ERROR : %s" % response.status_code)
    LOGI("[Holder] RESULT OF VP VERIFICATION: %s" % response.text)

######################################################################

createDIDDocument()
myJWT = didAuth(_ISSUER_URL)
vc_driverLicense = getVC(
    myJWT,
    DIDSAMPLE.ROLE['holder']['did'], 
    "schemaID1",
    "credentialDefinition1"
    )
LOGI("[Holder] USER CONFIRMATION : OK")
ackMessage(_ISSUER_URL, myJWT)
myJWT = didAuth(_ISSUER_URL)
vc_jejuPass = getVC(
    myJWT,
    DIDSAMPLE.ROLE['holder']['did'], 
    "schemaID2",
    "credentialDefinition2"
    )
LOGI("[Holder] USER CONFIRMATION : OK")
ackMessage(_ISSUER_URL, myJWT)

myJWT = didAuth(_ISSUER_URL)
vpPresentation = presentationProposal(myJWT)

LOGI("[Holder] READY FOR VP : %s" % vpPresentation)

vcArr = [vc_driverLicense, vc_jejuPass]
presentationProof(myJWT, vcArr)