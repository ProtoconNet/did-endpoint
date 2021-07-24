# -*- coding: utf-8 -*-
import ed25519
import base64
import base58
import requests
import random
import string
import json
import jwt
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

_CREDENTIAL_SUBJECTS = dict()

def makeVC(vc):
    if verifyVC(vc):
        return vc
    else:
        return None

#Todo
def verifyVC(vc):
    return True

def getUUID():
    return str(uuid.uuid4())

def signString(string, privateKeyB58):
    try:
        signing_key = ed25519.SigningKey(base58.b58decode(privateKeyB58))
        sig = signing_key.sign(string.encode("utf8"), encoding=None)
        sig_base58 = base58.b58encode(sig)
        sig_decoded = sig_base58.decode("utf-8")
        return sig_decoded
    except Exception:
        return None

def verifyString(string, signStr, pubkey):
    try:
        verifying_key = ed25519.VerifyingKey(base64.b64encode(base58.b58decode(pubkey)),
                                            encoding="base64")
        signedSignature_base58 = signStr
        signedSignature = base58.b58decode(signedSignature_base58)
        verifying_key.verify(signedSignature,
                         string.encode("utf8"),
                         encoding=None)
        return True
    except Exception:
        return False

def generateChallenge(size=32, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def saveCredentialSubject(uuid, credentialSubject):
    try:
        _CREDENTIAL_SUBJECTS[uuid] = credentialSubject
        return True
    except Exception:
        return False

def getCredentialSubject(uuid):
    try:
        credentialSubject = _CREDENTIAL_SUBJECTS[uuid]
        return credentialSubject
    except Exception:
        return None

def makeJWS(jsonBody, privateKeyB58):
    try :
        headerJSON = {"alg":"EdDSA","b64":False,"crit":["b64"]}
        header_base64 = base64.urlsafe_b64encode(json.dumps(headerJSON).encode('utf8'))
        header_ = header_base64.decode('utf8').rstrip("=")
        bodyString = json.dumps(jsonBody)
        sig_decoded = signString(bodyString, privateKeyB58)
        sig_base64 = base64.urlsafe_b64encode(base58.b58decode(sig_decoded))
        sig_ = sig_base64.decode('utf8').rstrip("=")
        return header_ + ".." + sig_
    except Exception:
        return None

def makeJWS_jwtlib(body,privateKeyB58):
    try:
        privatekeyOBJ = Ed25519PrivateKey.from_private_bytes(base58.b58decode(privateKeyB58))
        privatekeyPEM = privatekeyOBJ.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()) 
        encoded = jwt.encode(body, privatekeyPEM, algorithm="EdDSA")
        jwsArr = encoded.split(".")
        header = jwsArr[0]
        body = jwsArr[1]
        signature = jwsArr[2]
        jws = header + ".." + signature
    except Exception as ex:
        print(ex)
        print("YOU SHOULD INSTALL pyjwt >= 2.0.0 for EdDSA. 'pip install pyjwt==2'")
        return ex
    return jws

def verifyVP(vp, publicKeyB58):
    #1. VERIFY HOLDER 
    # PROBLEM : JWS는 줄바꿈이 없어야 한다
    # vp dump 한거는 
    jws = vp['proof'][0].pop('jws')
    dumpedVP = json.dumps(vp, separators=(',', ':')).encode('utf8')
    dumpedVPB64 = base64.urlsafe_b64encode(dumpedVP)
    dumpedVPB64decoded = dumpedVPB64.decode("utf-8").rstrip("=")
    return verifyJWS(jws, dumpedVPB64decoded, publicKeyB58)
    #2. TODO : VERIFY ISSUER

def verifyJWS(jws, bodyB64, publicKeyB58):
    try :
        publicKeyOBJ = Ed25519PublicKey.from_public_bytes(base58.b58decode(publicKeyB58))
        publickeySSH = publicKeyOBJ.public_bytes(encoding=Encoding.OpenSSH, format=PublicFormat.OpenSSH) 
        jwsArr = jws.split(".")
        header = jwsArr[0]
        tmpBody = jwsArr[1]
        signature = jwsArr[2]
        if tmpBody == '':
            body = bodyB64
        else :
            body = tmpBody
        restructuredJWS = header + "." + body + "." + signature
        try : 
            decoded = jwt.decode(restructuredJWS, publickeySSH, algorithms="EdDSA")
        except Exception as ex:
            print(ex)
            raise Exception("FAIL - verifyJWS - EN/DECRYPT PROBLEM")
    except Exception:
        raise Exception("FAIL - verifyJWS - FORMAT PROBLEM")
    return decoded

def getVerifiedJWT(request, secret):
    try :
        encoded_jwt = request.headers.get('Authorization')
    except Exception:
        return "NO Authorization"
    try :
        encoded_jwt = encoded_jwt.split(" ")[1] # FROM Bearer
    except Exception:
        return "NO Bearer : " + str(encoded_jwt)
    try :
        decoded_jwt = jwt.decode(encoded_jwt, secret, algorithms=["HS256"])
        return decoded_jwt
    except Exception:
        return "JWT verify failed"

def getPubkeyFromDIDDocument(documentURL):
    try:
        did_req = requests.get(documentURL) 
        pubkey = json.loads(json.loads(did_req.text)['data'])['verificationMethod'][0]['publicKeyBase58']
    except Exception:
        pubkey = json.loads(json.loads(did_req.text)['data'])['publicKey'][0]['publicKeyBase58']
    except Exception:
        pubkey = None
    return pubkey
