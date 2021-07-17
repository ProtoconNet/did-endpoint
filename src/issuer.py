# -*- coding: utf-8 -*-
import json
import bottle
import canister
import cherrypy as cp
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
LOG = DIDLOG.__get_logger('warning')
LOGI = LOG.info
LOGD = LOG.debug
LOGW = LOG.warning
LOGE = LOG.error

app = bottle.Bottle()
app.install(canister.Canister())

_ISSUER_DID = DIDSAMPLE.ROLE['issuer']['did']
_ISSUER_PRIVATEKEY = DIDSAMPLE.ROLE['issuer']['privateKey']
_ISSUER_SECRET = DIDSAMPLE.ROLE['issuer']['secret']
_ISSUER_DOMAIN = DIDSAMPLE.ROLE['issuer']['domain']
_ISSUER_PORT = DIDSAMPLE.ROLE['issuer']['port']
_ISSUER_URL =  _ISSUER_DOMAIN + ":" + str(_ISSUER_PORT) 
_PLATFORM_SCHEME_URL = DIDSAMPLE.ROLE['platform']['urls']['scheme']
_PLATFORM_RESOLVER_URL = DIDSAMPLE.ROLE['platform']['urls']['resolver']

@app.get('/VCScheme')
def VCScheme():
    try:
        scheme = request.query['scheme']
        schemeID = DID.getVCScheme(scheme)
        schemeJSON = json.dumps(
            {
                "scheme": _PLATFORM_SCHEME_URL+"?id="+schemeID,
                "VCPost": _ISSUER_URL+"/VC",
                "VCGet" : _ISSUER_URL+"/VC"
            })
    except Exception as ex :
        LOGE(ex)
        response.status = 404
        return "Error"
    LOGW("[Issuer] 1. VC Scheme 위치 알려주기 : %s" % (schemeJSON))
    raise HTTPResponse(schemeJSON, status=200, headers={})

@app.post('/VC')
def VCPost():
    try:
        vc = json.loads(request.body.read())
        myUUID = DID.getUUID()
        did = vc['did']
        credentialSubject = vc['credentialSubject']
        DID.saveCredentialSubject(myUUID, credentialSubject)
        challenge = DID.generateChallenge()
        documentURL = DIDSAMPLE.ROLE['platform']['urls']['document']+"?did="+did
        pubkey = DID.getPubkeyFromDIDDocument(did, documentURL)
        if pubkey == None:
            response.status = 404
            LOGE("[Issuer] 2. DID AUTH - Document Get 에러 발생 %s" % documentURL)
            return "Error"
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":pubkey, "challenge":challenge}, _ISSUER_SECRET, algorithm="HS256")
        LOGW("[Issuer] 2. DID AUTH - VC Post(%s) : 생성한 챌린지(%s), DID Document의 공개키(%s), Holder에게 JWT 발급(%s)." 
        % (credentialSubject, challenge, pubkey, encoded_jwt))
        try:
            str_jwt = str(encoded_jwt.decode("utf-8"))
        except Exception :
            #FOR PYJWT LEGACY
            str_jwt = encoded_jwt
    except Exception as ex :
        response.status = 404
        LOGE(ex)
        LOGW("[Issuer] 2. DID AUTH - VC Post에서 Exception 발생")
        return "Error"
    raise HTTPResponse(json.dumps({"payload": challenge, "endPoint":_ISSUER_URL+"/response"}), status=202, headers={'Authorization':str_jwt})

@app.get('/response')
def response():
    try:
        signature = request.query['signature']
        LOGI("[Issuer] 3. DID AUTH - Signature(%s)" % str(signature))
    except Exception:
        response.status = 400
        return "Error"
    try:
        jwt = DID.getVerifiedJWT(request, _ISSUER_SECRET)
        LOGI("[Issuer] 3. DID AUTH - jwt 결과(%s)" % str(jwt))
        challengeRet = DID.verifyString(jwt['challenge'] , signature, jwt['pubkey'])
        if challengeRet == True:
            LOGW("[Issuer] 3. DID AUTH - Verified : 사인 값(%s) 검증 성공." % signature)
        else:
            #TODO : Expired Token
            LOGW("[Issuer] 3. DID AUTH - Verify : Challenge(%s)의 사인 값(%s)을 pubkey(%s)로 검증 실패." % (jwt['challenge'] , signature, jwt['pubkey']))
    except Exception as ex :
        challengeRet = False
        LOGE(ex)
        LOGW("[Issuer] 3. DID AUTH - Verify : ERROR : 사인 검증 실패 : %s" % signature)
    raise HTTPResponse(json.dumps({"Response": challengeRet}), status=202, headers={})

@app.get('/VC')
def VCGet():
    try:
        jwt = DID.getVerifiedJWT(request, _ISSUER_SECRET)
        myUUID = jwt['uuid']
        credentialSubject = DID.getCredentialSubject(myUUID)
        # Todo : Change 'makeSampleVC' to 'makeVC'
        vc = DIDSAMPLE.makeSampleVC(_ISSUER_DID, credentialSubject)
        jws = DID.makeJWS(vc, _ISSUER_PRIVATEKEY)
        vc['proof']["jws"] = jws
    except Exception as ex :
        LOGE(ex)
        response.status = 404
        return "Error"
    LOGW("[Issuer] 4. VC Issuance - %s" % vc)
    raise HTTPResponse(json.dumps({"Response":True, "VC": vc}), status=202, headers={})

if __name__ == "__main__":
    #app.run(host='0.0.0.0', port=_ISSUER_PORT)
    cp.tree.graft(app, '/')
    cp.config.update({
        #'server.socket_host': _ISSUER_DOMAIN,
        'server.socket_port': _ISSUER_PORT,
        'server.thread_pool': 30
    })
    cp.server.start()

