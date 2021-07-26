# -*- coding: utf-8 -*-
import json
import bottle
import canister
import cherrypy
from bottle import response, request, HTTPResponse
import jwt
from tools import did as DID
from tools import log as DIDLOG
from configs import samples as DIDSAMPLE
try :
    # Monitoring :
    from configs import privates as DIDPRIVATE
    DIDLOG.init(DIDPRIVATE.LOG['sentryURL'])
except Exception:
    print('Not exist : configs/privates. LOG={"sentryURL" : "..."}')

# JUST Logging
LOG = DIDLOG.__get_logger('warning', 'verifier.log')
LOGI = LOG.info
LOGD = LOG.debug
LOGW = LOG.warning
LOGE = LOG.error

app = bottle.Bottle()
app.install(canister.Canister())

_VERIFIER_HOST = DIDSAMPLE.ROLE['verifier']['host']
_VERIFIER_PORT = DIDSAMPLE.ROLE['verifier']['port']
_VERIFIER_SECRET = DIDSAMPLE.ROLE['verifier']['secret']
_VERIFIER_URL =  "http://"+_VERIFIER_HOST + ":" + str(_VERIFIER_PORT) 

@app.get('/VPSchema')
def VPSchema():
    try:
        schema = request.query['schema']
        schemaID = DIDSAMPLE.getVPSchema(schema)
        schemaJSON = json.dumps(
            DIDSAMPLE.getVPSchemaJSON(schemaID)
        )
    except Exception as ex :
        LOGE(ex)
        response.status = 404
        return "Error"
    LOGW("[Verifier] 1. VP Schema 위치 알려주기 : %s" % (schemaJSON))
    raise HTTPResponse(schemaJSON, status=200, headers={})

def VPPost():
    try:
        response.status = 400
        data = json.loads(request.body.read())
        myUUID = DID.genUUID()
        did = data['did']
        vp = data['vp']
        challenge = DID.generateChallenge()
        documentURL = DIDSAMPLE.ROLE['platform']['urls']['document']+"?did="+did
        holder_pubkey = DID.getPubkeyFromDIDDocument(documentURL)
        if holder_pubkey == None:
            response.status = 400
            LOGE("[Issuer] 2. DID AUTH - Document Get 에러 발생 %s" % documentURL)
            return "Error - Holder pubkey"
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":holder_pubkey, "challenge":challenge}, _VERIFIER_SECRET, algorithm="HS256")
        try:
            str_jwt = str(encoded_jwt.decode("utf-8"))
        except Exception :
            #FOR PYJWT LEGACY
            str_jwt = encoded_jwt
        print(vp)
        DID.verifyVP(vp, holder_pubkey)
        vcs = DID.getVCSFromVP(vp)
        for vc in vcs:
            try:
                vcdid = DID.getDIDFromVC(vc)
                vcurl = DIDSAMPLE.getDIDDocumentURL(vcdid)
                vcpubkey = DID.getPubkeyFromDIDDocument(vcurl)
                DID.verifyVC(vc, vcpubkey)
            except Exception as ex :
                response.status = 401
                LOGE("[Verifier] 2-0. FAIL - Verify VC.")
                LOGE(ex)
                return "Error - VC"
        LOGW("[Verifier] 2-1. Verify VC, VP - VP Post(%s) : 생성한 챌린지(%s), DID Document의 공개키(%s), Holder에게 JWT 발급(%s)." 
        % (vp, challenge, holder_pubkey, encoded_jwt))
    except Exception as ex :
        response.status = 402
        LOGE(ex)
        LOGW("[Verifier] 2-1. VP Post에서 Exception 발생")
        return "Error - VP"
    response.status = 200
    DID.saveUUIDStatus(myUUID, True)
    raise HTTPResponse(json.dumps({"payload": challenge, "endPoint":_VERIFIER_URL+"/response"}), status=202, headers={'Authorization':str_jwt})

@app.get('/response')
def response():
    try:
        signature = request.query['signature']
        LOGI("[Verifier] 3. DID AUTH - Signature(%s)" % str(signature))
    except Exception:
        response.status = 400
        return "Error"
    try:
        jwt = DID.getVerifiedJWT(request, _VERIFIER_SECRET)
        LOGI("[Verifier] 3. DID AUTH - jwt 결과(%s)" % str(jwt))
        challengeRet = DID.verifyString(jwt['challenge'] , signature, jwt['pubkey'])
        if challengeRet == True:
            LOGW("[Verifier] 3. DID AUTH - Verified : 사인 값(%s) 검증 성공." % signature)
        else:
            DID.saveUUIDStatus(jwt['uuid'], False)
            LOGW("[Verifier] 3. DID AUTH - Verify : Challenge(%s)의 사인 값(%s)을 pubkey(%s)로 검증 실패." % (jwt['challenge'] , signature, jwt['pubkey']))
    except Exception as ex :
        response.status = 401
        challengeRet = False
        DID.saveUUIDStatus(jwt['uuid'], False)
        LOGE(ex)
        LOGW("[Verifier] 3. DID AUTH - Verify : ERROR : 사인 검증 실패 : %s" % signature)
        return "Error - DID Auth"
    raise HTTPResponse(json.dumps({"Response": challengeRet}), status=202, headers={})

def VPGet():
    try:
        jwt = DID.getVerifiedJWT(request, _VERIFIER_SECRET)
        if DID.getUUIDStatus(jwt['uuid']) == False:
            response.status = 401
            return "Error - Expired UUID"
    except Exception as ex :
        LOGE(ex)
        response.status = 404
        return "Error - NOT VERIFIED"
    LOGW("[Issuer] 4. Verified VP - %s" % jwt)
    raise HTTPResponse(json.dumps({"Response":True}), status=202, headers={})

@app.post('/vp1')
def postVP1():
    return VPPost()

@app.get('/vp1')
def getVP1():
    return VPGet()
    
if __name__ == "__main__":
    cherrypy.tree.graft(app, '/')
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'server.socket_port': _VERIFIER_PORT,
        'server.thread_pool': 30
    })
    cherrypy.server.start()
