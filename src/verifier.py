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

_HOST = DIDSAMPLE.ROLE['verifier']['host']
_PORT = DIDSAMPLE.ROLE['verifier']['port']
_WEB_PORT = DIDSAMPLE.ROLE['verifier']['webPort']
_SECRET = DIDSAMPLE.ROLE['verifier']['secret']
_URL =  "http://"+_HOST + ":" + str(_PORT) 

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
        urls = DIDSAMPLE.ROLE['verifier']['urls']
        status = 200
        LOGW("[Verifier] 1. 모든 위치 알려주기 : %s" % (urls))
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
            LOGE("[Verifier] 1. didAuth - 에러 발생 %s" % data)
            status = 400
            return HTTPResponse(status=status)
        # DID.saveCredentialSubject(myUUID, credentialSubject)
        if did == DIDSAMPLE.ROLE["holder"]["did"]:
            challenge = DIDSAMPLE.ROLE["verifier"]["challenge"] # FOR TEST
        else:
            challenge = DID.generateChallenge()
        documentURL = DIDSAMPLE.getDIDDocumentURL(did)
        pubkey = DID.getPubkeyFromDIDDocument(documentURL)
        if pubkey == None:
            LOGE("[Verifier] 2. DID AUTH - Document Get 에러 발생 %s" % documentURL)
            status = 404
            return HTTPResponse(status=status)
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":pubkey, "challenge":challenge}, _SECRET, algorithm="HS256")
        LOGW("[Verifier] 2. DID AUTH - VC Post : 생성한 챌린지(%s), DID Document의 공개키(%s), Holder에게 JWT 발급(%s)." 
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
        LOGW("[Verifier] 2. DID AUTH - VC Post에서 Exception 발생")
        status = 403
        return HTTPResponse(status=status)
    DID.saveUUIDStatus(myUUID, True)
    return HTTPResponse(json.dumps({"payload": challenge, "endPoint":_URL+"/didAuth"}), status=203, headers={'Authorization':str_jwt})

@app.get('/didAuth')
def res():
    try:
        signature = request.query['signature']
        LOGI("[Verifier] 3. DID AUTH - Signature(%s)" % str(signature))
    except Exception:
        status = 400
        return HTTPResponse(status=status)
    try:
        if checkJWT() == False:
            return HTTPResponse(status=410, headers={})
        jwt = DID.getVerifiedJWT(request, _SECRET)
        LOGI("[Verifier] 3. DID AUTH - jwt 결과(%s)" % str(jwt))
        challengeRet = DID.verifyString(jwt['challenge'] , signature, jwt['pubkey'])
        if challengeRet == True:
            LOGW("[Verifier] 3. DID AUTH - Verified : 사인 값(%s) 검증 성공." % signature)
            status = 200
        else:
            DID.saveUUIDStatus(jwt['uuid'], False)
            LOGW("[Verifier] 3. DID AUTH - Verify : Challenge(%s)의 사인 값(%s)을 pubkey(%s)로 검증 실패." % (jwt['challenge'] , signature, jwt['pubkey']))
            status = 401
        return HTTPResponse(json.dumps({"Response": challengeRet}), status=status, headers={})
    except Exception as ex :
        challengeRet = False
        DID.saveUUIDStatus(jwt['uuid'], False)
        LOGE(ex)
        LOGW("[Verifier] 3. DID AUTH - Verify : ERROR : 사인 검증 실패 : %s" % signature)
        status = 403
        return HTTPResponse(json.dumps({"Response": challengeRet}), status=status, headers={})

@app.get('/presentationProposal')
def presentationProposal():
    status = 200
    try:
        if checkJWT() == False:
            return HTTPResponse(status=410, headers={})
        did = request.query['did']
        presentationRequest = DIDSAMPLE._PRESENTATION_REQEUST
        return HTTPResponse(json.dumps(presentationRequest), status=status, headers={})
    except Exception as ex :
        status = 400
        return HTTPResponse(status=status, headers={})

@app.post('/presentationProof')
def PresentationProof():
    try:
        status = 400
        if checkJWT() == False:
            return HTTPResponse(status=410, headers={})
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
            status = 402
            LOGE("[Verifier] 2. DID AUTH - Document Get 에러 발생 %s" % documentURL)
            rowData = {"name":name, "status":status, "result":result, "verify":verify}
            _REQUEST_LIST.append(rowData)
            socketio.emit('broadcasting',rowData, broadcast=True)
            return HTTPResponse(status=status)
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
    return HTTPResponse(json.dumps({"result": True}), status=status)


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
        return HTTPResponse(json.dumps({"Response":True}), status=status, headers={})
    except Exception as ex :
        return HTTPResponse(status=status, headers={})


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
        'server.socket_port': _PORT,
        'server.thread_pool': 30
    })
    cherrypy.server.start()
    socketio.run(appFlask, host='0.0.0.0', port=8080)







