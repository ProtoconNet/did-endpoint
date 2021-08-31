import pytest
import sys, os
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from tools import did as DID
from configs import samples as DIDSAMPLE

def test_pastExpire():
    past = DID.getTime()
    result = DID.isExpired(past)
    assert (result) == True
        
def test_futureExpire():
    future = DIDSAMPLE.addTime(1)
    result = DID.isExpired(future)
    assert (result) == False

def test_DIDAuth_Success():
    challenge = DID.generateChallenge()
    signedChallenge = DID.signString(challenge, DIDSAMPLE.ROLE['holder']['privateKey'])
    verified = DID.verifyString(challenge, signedChallenge, DIDSAMPLE.ROLE['holder']['publicKey'])
    assert verified

def test_DIDAuth_StringError_Fail():
    challenge = DID.generateChallenge()
    signedChallenge = DID.signString("FAIL_CHALLENGE", DIDSAMPLE.ROLE['holder']['privateKey'])
    verified = DID.verifyString(challenge, signedChallenge, DIDSAMPLE.ROLE['holder']['publicKey'])
    assert verified == False

def test_DIDAuth_PrivateKeyError_Fail():
    challenge = DID.generateChallenge()
    signedChallenge = DID.signString(challenge, "FAIL_PRIVKEY")
    verified = DID.verifyString(challenge, signedChallenge, DIDSAMPLE.ROLE['holder']['publicKey'])
    assert verified == False

def test_DIDAuth_PublicKeyError_Fail():
    challenge = DID.generateChallenge()
    signedChallenge = DID.signString(challenge, DIDSAMPLE.ROLE['holder']['privateKey'])
    verified = DID.verifyString(challenge, signedChallenge, "FAIL_PUBKEY")
    assert verified == False

def test_SaveAndLoad_CredentialSubject_Success():
    uuid = DID.genUUID()
    DID.saveCredentialSubject(uuid, {"TEST" : "SUCCESS"})
    load = DID.loadCredentialSubject(uuid)
    assert load["TEST"] == "SUCCESS"
    return load

def test_SaveAndLoad_UUIDStatus_Success():
    uuid = DID.genUUID()
    DID.saveUUIDStatus(uuid, "TEST")
    load = DID.loadUUIDStatus(uuid)
    assert load == "TEST"

def test_makeAndVerifyVC_Success():
    credentialSubject = test_SaveAndLoad_CredentialSubject_Success()
    vcType = DIDSAMPLE.getVCType('vc1')
    vc = DIDSAMPLE.makeSampleVCwithoutJWS(DIDSAMPLE.ROLE['issuer']['did'], vcType, credentialSubject)
    jws = DID.makeJWS_jwtlib(vc, DIDSAMPLE.ROLE['issuer']['privateKey'])
    vc['proof']["jws"] = jws
    DID.verifyVC(vc, DIDSAMPLE.ROLE['issuer']['publicKey'])
    return vc

def test_makeAndVerifyVC_OtherKey_Fail():
    credentialSubject = test_SaveAndLoad_CredentialSubject_Success()
    vcType = DIDSAMPLE.getVCType('vc1')
    vc = DIDSAMPLE.makeSampleVCwithoutJWS(DIDSAMPLE.ROLE['issuer']['did'], vcType, credentialSubject)
    jws = DID.makeJWS_jwtlib(vc, DIDSAMPLE.ROLE['issuer']['privateKey'])
    vc['proof']["jws"] = jws
    with pytest.raises(Exception, match=r".* PROBLEM"):
        DID.verifyVC(vc, DIDSAMPLE.ROLE['holder']['publicKey'])
    return vc


def test_makeAndVerifyVC_OtherString_Fail():
    credentialSubject = test_SaveAndLoad_CredentialSubject_Success()
    vcType = DIDSAMPLE.getVCType('vc1')
    vc = DIDSAMPLE.makeSampleVCwithoutJWS(DIDSAMPLE.ROLE['issuer']['did'], vcType, credentialSubject)
    jws = DID.makeJWS_jwtlib(vc, DIDSAMPLE.ROLE['issuer']['privateKey'])
    vc['proof']["test"] = "Fail"
    vc['proof']["jws"] = jws
    print("%s" % vc)
    with pytest.raises(Exception, match=r".* PROBLEM"):
        DID.verifyVC(vc, DIDSAMPLE.ROLE['issuer']['publicKey'])
    return vc