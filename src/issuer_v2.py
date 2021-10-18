# -*- coding: utf-8 -*-
import json
import bottle
import canister
import cherrypy
import requests
from bottle import response, request, HTTPResponse
import jwt
from tools import did as DID
from tools import log as DIDLOG
from tools import tool
from configs import samples as DIDSAMPLE

try :
    # Monitoring :
    from configs import privates as DIDPRIVATE
    DIDLOG.init(DIDPRIVATE.LOG['sentryURL'])
except Exception:
    print('Not exist : configs/privates. LOG={"sentryURL" : "..."}')

# JUST Logging
LOG = DIDLOG.__get_logger('warning', 'issuer.log')
LOGI = LOG.info
LOGD = LOG.debug
LOGW = LOG.warning
LOGE = LOG.error

app = bottle.Bottle()
app.install(canister.Canister())

_ISSUER_DID = DIDSAMPLE.ROLE['issuer']['did']
_ISSUER_PRIVATEKEY = DIDSAMPLE.ROLE['issuer']['privateKey']
_ISSUER_SECRET = DIDSAMPLE.ROLE['issuer']['secret']
_ISSUER_HOST = DIDSAMPLE.ROLE['issuer']['host']
_ISSUER_PORT = DIDSAMPLE.ROLE['issuer']['port']
_ISSUER_URL =  "http://"+_ISSUER_HOST + ":" + str(_ISSUER_PORT) 

def initDID():
    URL = DIDSAMPLE.ROLE['platform']['urls']['document']
    data = DIDSAMPLE.makeSampleDIDDocument("issuer", "Ed25519VerificationKey2018")
    response = requests.post(URL, data=json.dumps(data))
    LOGI("[Issuer]0. Create DID Document : %s, Data : %s, Response : %s " % (data['id'], data, response))
    buyID = DID.genUUID()
    schemaID1 = createSchema(
        DIDSAMPLE._SCHEMA['vc1']['schemaName'], 
        DIDSAMPLE._SCHEMA['vc1']['version'], 
        DIDSAMPLE._SCHEMA['vc1']['attribute'], 
    )
    schemaID2 = createSchema(
        DIDSAMPLE._SCHEMA['vc2']['schemaName'], 
        DIDSAMPLE._SCHEMA['vc2']['version'], 
        DIDSAMPLE._SCHEMA['vc2']['attribute'], 
    )
    createCredentialDefinition(schemaID1, "vc1", False)
    createCredentialDefinition(schemaID2, "vc2", False)

def createSchema(schemaName, version, attribute):
    URL = DIDSAMPLE.ROLE['platform']['urls']['createSchema']
    data = {schemaName : schemaName, version : version, attribute : attribute}
    response = requests.post(URL, data=json.dumps(data))
    LOGI("[Issuer]0-0. Create Schema : %s " % (response))
    DID.saveSchema(response.schemaID, data)
    return response.schemaID

def createCredentialDefinition(schemaID, tag, revocation):
    URL = DIDSAMPLE.ROLE['platform']['urls']['createDefinition']
    data = {schemaID : schemaID, tag : tag, revocation : revocation}
    response = requests.post(URL, data=json.dumps(data))
    LOGI("[Issuer]0-1. Create Definition : %s " % (response))
    DID.saveCredentialDefinition(response.credDefID, data)
    return response.credDefID

# @app.get('/VCSchema')
# def VCSchema():
#     try:
#         schema = request.query['schema']
#         schemaID = DIDSAMPLE.getVCSchema(schema)
#         schemaJSON = json.dumps(
#             DIDSAMPLE.getVCSchemaJSON(schemaID)
#         )
#         status = 200
#     except Exception as ex :
#         LOGE(ex)
#         status = 404
#         return HTTPResponse(status=status, headers={})
#     LOGW("[Issuer] 1. VC Schema 위치 알려주기 : %s" % (schemaJSON))
#     return HTTPResponse(schemaJSON, status=status, headers={})

def VCPost():
    try:
        vc = json.loads(request.body.read())
        myUUID = DID.genUUID()
        try:
            did = vc['did']
            # credentialSubject = vc['credentialSubject']
            
            # TODO : FOR SAMPLE
            # existBuyID = tool.isExistKeyInObj('buyID', credentialSubject)
            # if existBuyID:
            #     credentialSubject = DIDSAMPLE.ROLE['holder']['credentialSubject']['jejuPass']
            # existDriverLicense = tool.isExistKeyInObj('driver’s license', credentialSubject)
            # if existDriverLicense: # and credentialSubject['driver’s license'] == '':
            #     credentialSubject = DIDSAMPLE.ROLE['holder']['credentialSubject']['driverLicense']
            #####################
        except Exception:
            LOGE("[Issuer] 2. VC POST - 에러 발생 %s" % vc)
            status = 400
            return HTTPResponse(status=status)
        # DID.saveCredentialSubject(myUUID, credentialSubject)
        challenge = DID.generateChallenge()
        documentURL = DIDSAMPLE.getDIDDocumentURL(did)
        pubkey = DID.getPubkeyFromDIDDocument(documentURL)
        if pubkey == None:
            LOGE("[Issuer] 2. DID AUTH - Document Get 에러 발생 %s" % documentURL)
            status = 404
            return HTTPResponse(status=status)
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":pubkey, "challenge":challenge}, _ISSUER_SECRET, algorithm="HS256")
        LOGW("[Issuer] 2. DID AUTH - VC Post : 생성한 챌린지(%s), DID Document의 공개키(%s), Holder에게 JWT 발급(%s)." 
        % (challenge, pubkey, encoded_jwt))
        try:
            str_jwt = str(encoded_jwt.decode("utf-8"))
            status = 200
        except Exception :
            #FOR PYJWT LEGACY
            str_jwt = encoded_jwt
            status = 200
    except Exception as ex :
        LOGE(ex)
        LOGW("[Issuer] 2. DID AUTH - VC Post에서 Exception 발생")
        status = 403
        return HTTPResponse(status=status)
    DID.saveUUIDStatus(myUUID, True)
    return HTTPResponse(json.dumps({"payload": challenge, "endPoint":_ISSUER_URL+"/response"}), status=status, headers={'Authorization':str_jwt})

@app.get('/response')
def res():
    try:
        signature = request.query['signature']
        LOGI("[Issuer] 3. DID AUTH - Signature(%s)" % str(signature))
    except Exception:
        status = 400
        return HTTPResponse(status=status)
    try:
        jwt = DID.getVerifiedJWT(request, _ISSUER_SECRET)
        LOGI("[Issuer] 3. DID AUTH - jwt 결과(%s)" % str(jwt))
        challengeRet = DID.verifyString(jwt['challenge'] , signature, jwt['pubkey'])
        if challengeRet == True:
            LOGW("[Issuer] 3. DID AUTH - Verified : 사인 값(%s) 검증 성공." % signature)
            status = 200
        else:
            DID.saveUUIDStatus(jwt['uuid'], False)
            LOGW("[Issuer] 3. DID AUTH - Verify : Challenge(%s)의 사인 값(%s)을 pubkey(%s)로 검증 실패." % (jwt['challenge'] , signature, jwt['pubkey']))
            status = 401
    except Exception as ex :
        challengeRet = False
        DID.saveUUIDStatus(jwt['uuid'], False)
        LOGE(ex)
        LOGW("[Issuer] 3. DID AUTH - Verify : ERROR : 사인 검증 실패 : %s" % signature)
        status = 403
    return HTTPResponse(json.dumps({"Response": challengeRet}), status=status, headers={})

@app.get('/credentialProposal')
def credentialProposal():
    status = 404
    try:
        jwt = DID.getVerifiedJWT(request, _ISSUER_SECRET)
        schemaID = request.query['schemaID']
        credefID = request.query['credefID']
        did = request.query['DID']
        # attributes = DID.loadAttributes(did, schemaID, credefID)
        schema = DID.loadSchema(schemaID)
        vcType = schema["schemaName"] 
        attributes  = DIDSAMPLE.ROLE['holder']['credentialSubject'][vcType]
        #vcSample = DIDSAMPLE.makeSampleVCwithoutJWS(_ISSUER_DID, vcType, attributes)
        status = 200
    except Exception as ex :
        status = 400
        return HTTPResponse(status=status, headers={})
    return HTTPResponse(json.dumps({"Response":True, "credentialAttributeValueList": attributes}), status=status, headers={})

@app.get('/credentialRequest')
def credentialRequest():
    status = 404
    try:
        jwt = DID.getVerifiedJWT(request, _ISSUER_SECRET)
        schemaID = request.query['schemaID']
        credefID = request.query['credefID']
        did = request.query['DID']
        # attributes = DID.loadAttributes(did, schemaID, credefID)
        schema = DID.loadSchema(schemaID)
        vcType = schema["schemaName"] 
        attributes  = DIDSAMPLE.ROLE['holder']['credentialSubject'][vcType]
        vc = DIDSAMPLE.makeSampleVCwithoutJWS(_ISSUER_DID, vcType, attributes)
        jws = DID.makeJWS_jwtlib(vc, _ISSUER_PRIVATEKEY)
        vc['proof']["jws"] = jws
        status = 200
    except Exception as ex :
        status = 400
        return HTTPResponse(status=status, headers={})
    return HTTPResponse(json.dumps({"Response":True, "VC": vc}), status=status, headers={})


def VCGet(vcType): ## getCredentialProposal
    try:
        jwt = DID.getVerifiedJWT(request, _ISSUER_SECRET)
        myUUID = jwt['uuid']
        if DID.loadUUIDStatus(myUUID) == False:
            status = 404
            return HTTPResponse(status=status, headers={})
        credentialSubject = DID.loadCredentialSubject(myUUID)
        vc = DIDSAMPLE.makeSampleVCwithoutJWS(_ISSUER_DID, vcType , credentialSubject)
        jws = DID.makeJWS_jwtlib(vc, _ISSUER_PRIVATEKEY)
        vc['proof']["jws"] = jws
        status = 200
    except Exception as ex :
        LOGE(ex)
        status = 400
        try:
            DID.saveUUIDStatus(myUUID, False)
        except Exception as ex :
            LOGE(ex)
            status = 401
        return HTTPResponse(status=status, headers={})
    LOGW("[Issuer] 4. VC Issuance - %s" % vc)
    return HTTPResponse(json.dumps({"Response":True, "VC": vc}), status=status, headers={})

def buyPost():
    try:
        buyInfo = json.loads(request.body.read())
        buyID = DID.genUUID()
        DIDSAMPLE.saveBuySample(buyID, buyInfo)
        status = 200
        LOGW("[Issuer] 0. Buy JejuPass. buyID : %s, buyInfo : %s" % (buyID, buyInfo))
        return HTTPResponse(json.dumps({"Response":True, "buyID": buyID}), status=status, headers={})
    except Exception as ex:
        LOGE(ex)
        status = 402    
        return HTTPResponse(json.dumps({"Response":False}), status=status, headers={})

def buyGet():
    try :
        buyID = request.query['buyID']
        DIDSAMPLE.loadBuySample(buyID)
    except Exception as ex:
        LOGE(ex)
        status = 404
        return HTTPResponse(json.dumps({"result":False}), status=status, headers={})

@app.post('/vc1')
def postVC1():
    return VCPost()

@app.post('/vc2')
def postVC2():
    return VCPost()

@app.get('/vc1')
def getVC1():
    return VCGet(DIDSAMPLE.getVCType('vc1'))

@app.get('/vc2')
def getVC2():
    return VCGet(DIDSAMPLE.getVCType('vc2'))

@app.post('/jejuPass')
def buyPassPost():
    return buyPost()

@app.get('/jejuPass')
def buyPassGet():
    return buyGet()

if __name__ == "__main__":
    #app.run(host='0.0.0.0', port=_ISSUER_PORT)
    initDID()
    cherrypy.tree.graft(app, '/')
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'server.socket_port': _ISSUER_PORT,
        'server.thread_pool': 30
    })
    cherrypy.server.start()

