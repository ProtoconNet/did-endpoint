# -*- coding: utf-8 -*-
import json
import bottle
import canister
import cherrypy
import requests
from bottle import response, request, HTTPResponse
from urllib.parse import urlparse, parse_qs
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
_SECRET = DIDSAMPLE.ROLE['issuer']['secret']
_HOST = DIDSAMPLE.ROLE['issuer']['host']
_PORT = DIDSAMPLE.ROLE['issuer']['port']
_URL =  "http://"+_HOST + ":" + str(_PORT) 

def initDID():
    URL = DIDSAMPLE.ROLE['platform']['urls']['document']
    data = DIDSAMPLE.makeSampleDIDDocument("issuer", "Ed25519VerificationKey2018")
    response = requests.post(URL, data=json.dumps(data))
    LOGI("[Issuer]0. Create DID Document : %s, Data : %s, Response : %s " % (data['id'], data, response))
    buyID = DID.genUUID()
    schemaID1 = createSchema(
        DIDSAMPLE._SCHEMA['schemaID1']['schemaName'], 
        DIDSAMPLE._SCHEMA['schemaID1']['version'], 
        DIDSAMPLE._SCHEMA['schemaID1']['attribute'], 
    )
    DID.saveSchema("schemaID1", DIDSAMPLE._SCHEMA['schemaID1'])
    DID.saveSchema("schemaID2", DIDSAMPLE._SCHEMA['schemaID2'])
    schemaID2 = createSchema(
        DIDSAMPLE._SCHEMA['schemaID2']['schemaName'], 
        DIDSAMPLE._SCHEMA['schemaID2']['version'], 
        DIDSAMPLE._SCHEMA['schemaID2']['attribute'], 
    )
    createCredentialDefinition(schemaID1, "schemaID1", False)
    createCredentialDefinition(schemaID2, "schemaID2", False)

    DID.saveCredentialDefinition("credentialDefinitionID1", DIDSAMPLE._CREDENTIALDEFINITION['credentialDefinitionID1'])
    DID.saveCredentialDefinition("credentialDefinitionID2", DIDSAMPLE._CREDENTIALDEFINITION['credentialDefinitionID2'])

def createSchema(schemaName, version, attribute):
    try:
        URL = DIDSAMPLE.ROLE['platform']['urls']['createSchema']
        data = {"schemaName" : schemaName, "version" : version, "attribute" : attribute}
        response = requests.post(URL, data=json.dumps(data))
        text = json.loads(response.text)
        DID.saveSchema(text["id"], data)
        LOGW("[Issuer]0-0. Create Schema : %s " % (response.text))
        return text["id"]
    except Exception as ex:
        LOGE(ex)
        return "schemaID"
    
def createCredentialDefinition(schemaID, tag, revocation):
    try : 
        URL = DIDSAMPLE.ROLE['platform']['urls']['createDefinition']
        data = {"schemaID" : schemaID, "tag" : tag, "revocation" : revocation}
        response = requests.post(URL, data=json.dumps(data))
        text = json.loads(response.text)
        DID.saveCredentialDefinition(text["id"], data)
        LOGW("[Issuer]0-1. Create Definition : %s " % (response.text))
        return text["id"]
    except Exception as ex :
        LOGE(ex)
        return "credentialDefinition"


def checkJWT():
    try:
        jwt = DID.getVerifiedJWT(request, _SECRET)
        myUUID = jwt['uuid']
        return DID.loadUUIDStatus(myUUID)
    except:
        return False
        
@app.get('/urls')
def urls():
    try:
        urls = DIDSAMPLE.ROLE['issuer']['urls']
        status = 200
        LOGW("[Issuer] 1. 모든 위치 알려주기 : %s" % (urls))
        return HTTPResponse(json.dumps(urls), status=status, headers={})
    except Exception as ex :
        LOGE(ex)
        status = 404
        return HTTPResponse(status=status, headers={})

@app.post('/didAuth')
def DIDAuth(): ########### DID AUTH
    try:
        data = json.loads(request.body.read())
        myUUID = DID.genUUID()
        try:
            did = data['did']
        except Exception:
            LOGE("[Issuer] 1. didAuth - 에러 발생 %s" % data)
            status = 400
            return HTTPResponse(status=status)
        # DID.saveCredentialSubject(myUUID, credentialSubject)
        if did == DIDSAMPLE.ROLE["holder"]["did"]:
            challenge = DIDSAMPLE.ROLE["issuer"]["challenge"] # FOR TEST
        else:
            challenge = DID.generateChallenge()
        documentURL = DIDSAMPLE.getDIDDocumentURL(did)
        pubkey = DID.getPubkeyFromDIDDocument(documentURL)
        if pubkey == None:
            LOGE("[Issuer] 1. DID AUTH - Document Get 에러 발생 %s" % documentURL)
            status = 404
            return HTTPResponse(status=status)
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":pubkey, "challenge":challenge}, _SECRET, algorithm="HS256")
        LOGW("[Issuer] 1. DID AUTH - VC Post : 생성한 챌린지(%s), DID Document의 공개키(%s), Holder에게 JWT 발급(%s)." 
        % (challenge, pubkey, encoded_jwt))
        try:
            str_jwt = str(encoded_jwt.decode("utf-8"))
            status = 201
        except Exception :
            #FOR PYJWT LEGACY
            str_jwt = encoded_jwt
            status = 202
    except Exception as ex :
        LOGE(ex)
        LOGW("[Issuer] 1. DID AUTH - VC Post에서 Exception 발생")
        status = 403
        return HTTPResponse(status=status)
    DID.saveUUIDStatus(myUUID, True)
    return HTTPResponse(json.dumps({"payload": challenge, "endPoint":_URL+"/didAuth"}), status=203, headers={'Authorization':str_jwt})

@app.get('/didAuth')
def didAuthRes():
    try:
        signature = request.query['signature']
        LOGI("[Issuer] 2. DID AUTH - Signature(%s)" % str(signature))
    except Exception:
        status = 400
        return HTTPResponse(status=status)
    try:
        if checkJWT() == False:
            return HTTPResponse(status=410, headers={})
        jwt = DID.getVerifiedJWT(request, _SECRET)
        LOGI("[Issuer] 2. DID AUTH - jwt 결과(%s)" % str(jwt))
        challengeRet = DID.verifyString(jwt['challenge'] , signature, jwt['pubkey'])
        if challengeRet == True:
            LOGW("[Issuer] 2. DID AUTH - Verified : 사인 값(%s) 검증 성공." % signature)
            status = 200
        else:
            DID.saveUUIDStatus(jwt['uuid'], False)
            LOGW("[Issuer] 2. DID AUTH - Verify : Challenge(%s)의 사인 값(%s)을 pubkey(%s)로 검증 실패." % (jwt['challenge'] , signature, jwt['pubkey']))
            status = 401
        return HTTPResponse(json.dumps({"Response": challengeRet}), status=status, headers={})
    except Exception as ex :
        challengeRet = False
        DID.saveUUIDStatus(jwt['uuid'], False)
        LOGE(ex)
        LOGW("[Issuer] 2. DID AUTH - Verify : ERROR : %s" % signature)
        status = 403

@app.get('/credentialProposal')
def credentialProposal():
    status = 404
    try:
        if checkJWT() == False:
            return HTTPResponse(status=410, headers={})
        schemaID = request.query['schemaID']
        credefID = request.query['creDefId']
        did = request.query['did']
        # attributes = DID.loadAttributes(did, schemaID, credefID)
        schema = DID.loadSchema(schemaID)
        vcType = schema["schemaName"] 
        attributes  = DIDSAMPLE.ROLE['holder']['credentialSubject'][vcType]
        #vcSample = DIDSAMPLE.makeSampleVCwithoutJWS(_ISSUER_DID, vcType, attributes)
        status = 200
        LOGW("[Issuer] 3. VC LOG : did : (%s), schemaID:(%s), credefID(%s), attributes (%s) ",did, schemaID, credefID, attributes)
        return HTTPResponse(json.dumps({"Response":True, "credentialAttributeValueList": attributes}), status=status, headers={})
    except Exception as ex :
        status = 400
        LOGE(ex)
        return HTTPResponse(status=status, headers={})
    

@app.get('/credentialRequest')
def credentialRequest():
    status = 400
    try:
        if checkJWT() == False:
            return HTTPResponse(status=410, headers={})
        try:
            schemaID = request.query['schemaID']
            credefID = request.query['credefID']
            did = request.query['did']
        except Exception :
            status = 404
        # attributes = DID.loadAttributes(did, schemaID, credefID)
        schema = DID.loadSchema(schemaID)
        vcType = schema["schemaName"] 
        attributes  = DIDSAMPLE.ROLE['holder']['credentialSubject'][vcType]
        vc = DIDSAMPLE.makeSampleVCwithoutJWS(_ISSUER_DID, vcType, attributes)
        jws = DID.makeJWS_jwtlib(vc, _ISSUER_PRIVATEKEY)
        vc['proof']["jws"] = jws
        status = 200
        LOGW("[Issuer] 4. Verifiable Credential (%s) ", vc)
        return HTTPResponse(json.dumps({"Response":True, "VC": vc}), status=status, headers={})
    except Exception as ex :
        LOGE(ex)
        return HTTPResponse(status=status, headers={})

@app.get('/ackMessage')
def ack():
    status = 400
    try:
        jwt = DID.getVerifiedJWT(request, _SECRET)
        myUUID = jwt['uuid']
        if DID.loadUUIDStatus(myUUID) == False:
            status = 410
            return HTTPResponse(status=status, headers={})
        if DID.deleteUUIDStatus(myUUID) == True:
            status = 200   
        else :
            status = 401
        LOGW("5. ack Response : (%s)", True)
        return HTTPResponse(json.dumps({"Response":True}), status=status, headers={})
    except Exception as ex :
        LOGW(ex)
        return HTTPResponse(status=status, headers={})

def VCGet(vcType): ## getCredentialProposal
    try:
        jwt = DID.getVerifiedJWT(request, _SECRET)
        myUUID = jwt['uuid']
        if DID.loadUUIDStatus(myUUID) == False:
            status = 410
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

@app.post('/buyProtoconPass')
def buyPost():
    try:
        buyInfo = json.loads(request.body.read())
        buyID = DID.genUUID()
        DIDSAMPLE.saveBuySample(buyID, buyInfo)
        status = 200
        LOGW("[Issuer] 0. Buy ProtoconPass. buyID : %s, buyInfo : %s" % (buyID, buyInfo))
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


# @app.post('/vc1')
# def postVC1():
#     return VCPost()

# @app.post('/vc2')
# def postVC2():
#     return VCPost()

@app.get('/vc1')
def getVC1():
    return VCGet(DIDSAMPLE.getVCType('vc1'))

@app.get('/vc2')
def getVC2():
    return VCGet(DIDSAMPLE.getVCType('vc2'))

@app.post('/protoconPass')
def buyPassPost():
    return buyPost()

@app.get('/protoconPass')
def buyPassGet():
    return buyGet()

if __name__ == "__main__":
    #app.run(host='0.0.0.0', port=_PORT)
    initDID()
    cherrypy.tree.graft(app, '/')
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'server.socket_port': _PORT,
        'server.thread_pool': 30
    })
    cherrypy.server.start()

