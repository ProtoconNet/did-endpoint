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
        data = json.loads(request.body.read())
        myUUID = DID.getUUID()
        did = data['did']
        vp = data['vp']
        challenge = DID.generateChallenge()
        documentURL = DIDSAMPLE.ROLE['platform']['urls']['document']+"?did="+did
        pubkey = DID.getPubkeyFromDIDDocument(documentURL)
        if pubkey == None:
            response.status = 404
            LOGE("[Issuer] 2. DID AUTH - Document Get 에러 발생 %s" % documentURL)
            return "Error"
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":pubkey, "challenge":challenge}, _VERIFIER_SECRET, algorithm="HS256")
        try:
            str_jwt = str(encoded_jwt.decode("utf-8"))
        except Exception :
            #FOR PYJWT LEGACY
            str_jwt = encoded_jwt
        print(vp)
        DID.verifyVP(vp, pubkey)
        LOGW("[Verifier] 2. Verify VP - VP Post(%s) : 생성한 챌린지(%s), DID Document의 공개키(%s), Holder에게 JWT 발급(%s)." 
        % (vp, challenge, pubkey, encoded_jwt))
    except Exception as ex :
        response.status = 404
        LOGE(ex)
        LOGW("[Verifier] 2. VP Post에서 Exception 발생")
        return "Error"
    raise HTTPResponse(json.dumps({"payload": challenge, "endPoint":_VERIFIER_URL+"/response"}), status=202, headers={'Authorization':str_jwt})

@app.post('/vp1')
def postVP1():
    return VPPost()

    
if __name__ == "__main__":
    cherrypy.tree.graft(app, '/')
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'server.socket_port': _VERIFIER_PORT,
        'server.thread_pool': 30
    })
    cherrypy.server.start()
