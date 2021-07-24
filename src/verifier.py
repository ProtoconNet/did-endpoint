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
LOG = DIDLOG.__get_logger('warning')
LOGI = LOG.info
LOGD = LOG.debug
LOGW = LOG.warning
LOGE = LOG.error

app = bottle.Bottle()
app.install(canister.Canister())

_VERIFIER_PORT = DIDSAMPLE.ROLE['verifier']['port']

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
        vp = json.loads(request.body.read())
        LOGW("[Verifier] 2. VP Post (%s)" % vp)
    except Exception as ex :
        response.status = 404
        LOGE(ex)
        LOGW("[Verifier] 2. VC Post에서 Exception 발생")
        return "Error"
    raise HTTPResponse(json.dumps({}), status=202, headers={})

@app.post('/vp1')
def postVP1():
    return VPPost()

    
if __name__ == "__main__":
    #app.run(host='0.0.0.0', port=_ISSUER_PORT)
    cherrypy.tree.graft(app, '/')
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'server.socket_port': _ISSUER_PORT,
        'server.thread_pool': 30
    })
    cherrypy.server.start()
