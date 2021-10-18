# -*- coding: utf-8 -*-
import json
import bottle
import canister
import cherrypy
from bottle import response, request, route, run, static_file, HTTPResponse
import jwt
import os
from flask import Flask, render_template, send_from_directory
from flask_socketio import SocketIO

from os.path import join, dirname
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

_REQUEST_LIST = [
    {"result":0, "name":'위근호',   "context":'유효하지 않은 운전면허증입니다. (+1)', "verify":[1,0,0], "date": '10월 1일'},
    {"result":0, "name":'위근호',   "context":'운전면허증 유효기간이 지났습니다.',    "verify":[1,0,1], "date":'10월 1일'},
    {"result":1, "name":'위근호',   "context":'고객 정보 검증이 완료되었습니다.',     "verify":[1,1,1], "date": '10월 1일'},
    {"result":1, "name":'Audrey', "context":'고객 정보 검증이 완료되었습니다.',    "verify":[1,1,1], "date":'10월 2일'},
    {"result":0, "name":'Audrey', "context":'DID 인증을 실패하였습니다.',       "verify":[0,1,1], "date":'10월 3일'},
    {"result":1, "name":'Audrey', "context":'고객 정보 검증이 완료되었습니다.',    "verify":[1,1,1], "date":'10월 3일'},
    {"result":0, "name":'Audrey', "context":'제주패스의 유효기간이 지났습니다.',    "verify": [1,1,0],"date":  '10월 3일'},
    {"result":0, "name":'Audrey', "context":'유효하지 않은 운전면허증입니다. (+1)',"verify":[1,0,0], "date":'10월 3일'},
    {"result":0, "name":'Audrey', "context":'운전면허증 유효기간이 지났습니다.',    "verify": [1,0,1],"date":  '10월 4일'},
    {"result":1, "name":'Audrey', "context":'고객 정보 검증이 완료되었습니다.',    "verify":[1,1,1], "date":'10월 4일'},
    {"result":1, "name":'Audrey', "context":'고객 정보 검증이 완료되었습니다.',    "verify":[1,1,1], "date":'10월 5일'},
    {"result":0, "name":'Audrey', "context":'DID 인증을 실패하였습니다.',       "verify":[0,1,1],  "date":'10월 5일'},
    {"result":1, "name":'Audrey', "context":'고객 정보 검증이 완료되었습니다.',    "verify":[1,1,1],  "date":'10월 6일'},
    {"result":0, "name":'Audrey', "context":'제주패스의 유효기간이 지났습니다.',    "verify":[1,1], "date":  '10월 7일'}
]


############### WEB & SOCKET IO ################
templateDir = os.path.dirname(__file__) + "/ui"
appFlask = Flask(__name__, template_folder=templateDir, static_folder=templateDir)
appFlask.config['SECRET_KEY'] = 'securekim'
socketio = SocketIO(appFlask)
socketio.init_app(appFlask, cors_allowed_origins="*")
###########################################

app = bottle.Bottle()
app.install(canister.Canister())

_VERIFIER_HOST = DIDSAMPLE.ROLE['verifier']['host']
_VERIFIER_PORT = DIDSAMPLE.ROLE['verifier']['port']
_VERIFIER_WEB_PORT = DIDSAMPLE.ROLE['verifier']['webPort']
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
        status = 200
    except Exception as ex :
        LOGE(ex)
        status = 400
        return HTTPResponse(status=status)
    LOGW("[Verifier] 1. VP Schema 위치 알려주기 : %s" % (schemaJSON))
    raise HTTPResponse(schemaJSON, status=status, headers={})


@app.get('/presentationProposal')
def presentationProposal():
    try:
        did = request.query['did']
    except Exception as ex :
        
    raise HTTPResponse(schemaJSON, status=status, headers={})

def VPPost():
    try:
        status = 400
        data = json.loads(request.body.read())
        myUUID = DID.genUUID()
        did = data['did']
        vp = data['vp']
        result = 0
        verify = []
        challenge = DID.generateChallenge()
        documentURL = DIDSAMPLE.ROLE['platform']['urls']['document']+"?did="+did
        holder_pubkey = DID.getPubkeyFromDIDDocument(documentURL)
        name = vp['verifiableCredential'][0]['credentialSubject']['name']
        if holder_pubkey == None:
            status = 404
            LOGE("[Issuer] 2. DID AUTH - Document Get 에러 발생 %s" % documentURL)
            rowData = {"name":name, "status":status, "result":result, "verify":verify}
            _REQUEST_LIST.append(rowData)
            socketio.emit('broadcasting',rowData, broadcast=True)
            return HTTPResponse(status=status)
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":holder_pubkey, "challenge":challenge}, _VERIFIER_SECRET, algorithm="HS256")
        try:
            str_jwt = str(encoded_jwt.decode("utf-8"))
        except Exception :
            #FOR PYJWT LEGACY
            str_jwt = encoded_jwt
        DID.verifyVP(vp, holder_pubkey)
        vcs = DID.getVCSFromVP(vp)
        verify.append(1)
        for vc in vcs:
            try:
                vcdid = DID.getDIDFromVC(vc)
                vcurl = DIDSAMPLE.getDIDDocumentURL(vcdid)
                vcpubkey = DID.getPubkeyFromDIDDocument(vcurl)
                DID.verifyVC(vc, vcpubkey)
                verify.append(1)
            except Exception as ex :
                status = 401
                LOGE("[Verifier] 2-0. FAIL - Verify VC.")
                LOGE(ex)
                rowData = {"name":name, "status":status, "result":result, "verify":verify}
                _REQUEST_LIST.append(rowData)
                socketio.emit('broadcasting',rowData, broadcast=True)
                return HTTPResponse(status=status)
        LOGW("[Verifier] 2-1. Verify VC, VP - VP Post(%s) : 생성한 챌린지(%s), DID Document의 공개키(%s), Holder에게 JWT 발급(%s)." 
        % (vp, challenge, holder_pubkey, encoded_jwt))
    except Exception as ex :
        status = 400
        LOGE(ex)
        LOGW("[Verifier] 2-1. VP Post에서 Exception 발생")
        rowData = {"name":name, "status":status, "result":result, "verify":verify}
        _REQUEST_LIST.append(rowData)
        socketio.emit('broadcasting',rowData, broadcast=True)
        return HTTPResponse(status=status)
    DID.saveUUIDStatus(myUUID, True)
    status = 200
    result = 1
    rowData = {"name":name, "status":status, "result":result, "verify":verify, "context":"고객 정보 검증이 완료되었습니다."}
    _REQUEST_LIST.append(rowData)
    socketio.emit('broadcasting',rowData, broadcast=True)
    return HTTPResponse(json.dumps({"payload": challenge, "endPoint":_VERIFIER_URL+"/response"}), status=status, headers={'Authorization':str_jwt})

@app.get('/response')
def response():
    try:
        signature = request.query['signature']
        LOGI("[Verifier] 3. DID AUTH - Signature(%s)" % str(signature))
    except Exception:
        status = 400
        return HTTPResponse(status=status)
    try:
        jwt = DID.getVerifiedJWT(request, _VERIFIER_SECRET)
        LOGI("[Verifier] 3. DID AUTH - jwt 결과(%s)" % str(jwt))
        challengeRet = DID.verifyString(jwt['challenge'] , signature, jwt['pubkey'])
        if challengeRet == True:
            LOGW("[Verifier] 3. DID AUTH - Verified : 사인 값(%s) 검증 성공." % signature)
            status = 200
        else:
            DID.saveUUIDStatus(jwt['uuid'], False)
            LOGW("[Verifier] 3. DID AUTH - Verify : Challenge(%s)의 사인 값(%s)을 pubkey(%s)로 검증 실패." % (jwt['challenge'] , signature, jwt['pubkey']))
            status = 404
    except Exception as ex :
        status = 403
        challengeRet = False
        DID.saveUUIDStatus(jwt['uuid'], False)
        LOGE(ex)
        LOGW("[Verifier] 3. DID AUTH - Verify : ERROR : 사인 검증 실패 : %s" % signature)
        return HTTPResponse(status=status)
    return HTTPResponse(json.dumps({"Response": challengeRet}), status=status, headers={})

def VPGet():
    try:
        jwt = DID.getVerifiedJWT(request, _VERIFIER_SECRET)
        if DID.loadUUIDStatus(jwt['uuid']) == False:
            status = 400
            return HTTPResponse(status=status)
    except Exception as ex :
        LOGE(ex)
        status = 404
        return HTTPResponse(status=status)
    LOGW("[Issuer] 4. Verified VP - %s" % jwt)
    status = 200
    return HTTPResponse(json.dumps({"Response":True}), status=status, headers={})

@app.post('/vp1')
def postVP1():
    return VPPost()

@app.get('/vp1')
def getVP1():
    return VPGet()
    
@appFlask.route('/')
def routeIndex():
    #socketio.emit('initList', _REQUEST_LIST, broadcast=True)
    return render_template("dashboard.html")

@appFlask.route("/<path:path>")
def static_dir(path):
    return send_from_directory(templateDir, path)

@socketio.on('initList')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    socketio.emit('initList', _REQUEST_LIST)

if __name__ == "__main__":
    cherrypy.tree.graft(app, '/')
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'server.socket_port': _VERIFIER_PORT,
        'server.thread_pool': 30
    })
    cherrypy.server.start()
    socketio.run(appFlask, host='0.0.0.0', port=8080)







