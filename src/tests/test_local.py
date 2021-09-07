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

def test_makeAndVerifyVC_DRIVER_Success():
    credentialSubject = test_SaveAndLoad_CredentialSubject_Success()
    vcType = DIDSAMPLE.getVCType('vc1')
    vc = DIDSAMPLE.makeSampleVCwithoutJWS(DIDSAMPLE.ROLE['issuer']['did'], vcType, credentialSubject)
    jws = DID.makeJWS_jwtlib(vc, DIDSAMPLE.ROLE['issuer']['privateKey'])
    vc['proof']["jws"] = jws
    DID.verifyVC(vc, DIDSAMPLE.ROLE['issuer']['publicKey'])
    return vc

def test_makeAndVerifyVC_JEJUPASS_Success():
    credentialSubject = test_SaveAndLoad_CredentialSubject_Success()
    vcType = DIDSAMPLE.getVCType('vc2')
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
    with pytest.raises(Exception, match=r".* PROBLEM"):
        DID.verifyVC(vc, DIDSAMPLE.ROLE['issuer']['publicKey'])
    return vc

def test_makeAndVerifyVP_Success():
    driverVC = test_makeAndVerifyVC_DRIVER_Success()
    jejuPassVC = test_makeAndVerifyVC_JEJUPASS_Success()
    vp = DIDSAMPLE.makeSampleVPwithoutJWS(DIDSAMPLE.ROLE['holder']['did'], [driverVC, jejuPassVC])
    vpJWS = DID.makeJWS_jwtlib(vp, DIDSAMPLE.ROLE['holder']['privateKey'])
    vp['proof'][0]["jws"] = vpJWS
    DID.verifyVP(vp, DIDSAMPLE.ROLE['holder']['publicKey'])
    vcs = DID.getVCSFromVP(vp)
    try:
        for vc in vcs:
            vcpubkey = DIDSAMPLE.ROLE['issuer']['publicKey']
            DID.verifyVC(vc, vcpubkey)
        assert True
    except Exception:
            pytest.fail("Unexpected Error ..")

def test_makeAndVerifyVP_OtherKey_Fail():
    driverVC = test_makeAndVerifyVC_DRIVER_Success()
    jejuPassVC = test_makeAndVerifyVC_JEJUPASS_Success()
    vp = DIDSAMPLE.makeSampleVPwithoutJWS(DIDSAMPLE.ROLE['holder']['did'], [driverVC, jejuPassVC])
    vpJWS = DID.makeJWS_jwtlib(vp, DIDSAMPLE.ROLE['holder']['privateKey'])
    vp['proof'][0]["jws"] = vpJWS
    with pytest.raises(Exception, match=r".* PROBLEM"):
        DID.verifyVP(vp, DIDSAMPLE.ROLE['issuer']['publicKey'])

def test_makeAndVerifyVP_OtherVCKey_Fail():
    driverVC = test_makeAndVerifyVC_DRIVER_Success()
    jejuPassVC = test_makeAndVerifyVC_JEJUPASS_Success()
    vp = DIDSAMPLE.makeSampleVPwithoutJWS(DIDSAMPLE.ROLE['holder']['did'], [driverVC, jejuPassVC])
    vpJWS = DID.makeJWS_jwtlib(vp, DIDSAMPLE.ROLE['holder']['privateKey'])
    vp['proof'][0]["jws"] = vpJWS
    DID.verifyVP(vp, DIDSAMPLE.ROLE['holder']['publicKey'])
    vcs = DID.getVCSFromVP(vp)
    try:
        for vc in vcs:
            vcpubkey = DIDSAMPLE.ROLE['holder']['publicKey']
            with pytest.raises(Exception, match=r".* PROBLEM"):
                DID.verifyVC(vc, vcpubkey)
        assert True
    except Exception:
            pytest.fail("Unexpected Error ..")

def test_makeAndVerifyVP_OtherData_Fail():
    driverVC = test_makeAndVerifyVC_DRIVER_Success()
    jejuPassVC = test_makeAndVerifyVC_JEJUPASS_Success()
    vp = DIDSAMPLE.makeSampleVPwithoutJWS(DIDSAMPLE.ROLE['holder']['did'], [driverVC, jejuPassVC])
    vpJWS = DID.makeJWS_jwtlib(vp, DIDSAMPLE.ROLE['holder']['privateKey'])
    vp['proof'][0]["jws"] = vpJWS
    vp['proof'][0]["test"] = "DUMMY"
    with pytest.raises(Exception, match=r".* PROBLEM"):
        DID.verifyVP(vp, DIDSAMPLE.ROLE['holder']['publicKey'])

def test_makeJWS_Success():
    body = {"TEST":"TEST"}
    jws = DID.makeJWS_jwtlib(body, DIDSAMPLE.ROLE['holder']['privateKey'])
    assert jws == "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9..psDksoXzs3Z81NZzQpGRVu1CaxAxJtVG-hXneyqtflHOwz3hAaJTBMSbOJzogWaCD-w3AHDXGtD745VRhVQlCQ"
    return jws

def test_makeJWS_String_Fail():
    bodyStr = "FAIL"
    with pytest.raises(Exception):
        DID.makeJWS_jwtlib(bodyStr, DIDSAMPLE.ROLE['holder']['privateKey'])

def test_verifyJWS_Success():
    jws = test_makeJWS_Success()
    body = {"TEST":"TEST"}
    bodyB64 = "eyJURVNUIjoiVEVTVCJ9"
    ret = DID.verifyJWS(jws, bodyB64, DIDSAMPLE.ROLE['holder']['publicKey'])
    assert ret == body

def test_verifyJWS_data_Fail():
    jws = test_makeJWS_Success()
    body = {"TEST":"TEST"}
    bodyB64 = "DUMMY"
    with pytest.raises(Exception):
        ret = DID.verifyJWS(jws, bodyB64, DIDSAMPLE.ROLE['holder']['publicKey'])

def test_verifyJWS_key_Fail():
    jws = test_makeJWS_Success()
    body = {"TEST":"TEST"}
    bodyB64 = "eyJURVNUIjoiVEVTVCJ9"
    with pytest.raises(Exception):
        DID.verifyJWS(jws, bodyB64, DIDSAMPLE.ROLE['issuer']['publicKey'])

def test_signStr_Success():
    string = "test"
    try:
        result = DID.signString(string, DIDSAMPLE.ROLE['holder']['privateKey'])
        assert True
        return result
    except Exception:
        assert False

def test_signStr_Key_Fail():
    string = "test"
    try:
        DID.signString(string, "DUMMY")
        assert True
    except Exception:
        assert False

def test_verifyStr_Success():
    string = "test"
    signString = test_signStr_Success()
    try:
        DID.verifyString(string, signString, DIDSAMPLE.ROLE['holder']['publicKey'])
        assert True
    except Exception:
        assert False

def test_verifyStr_Data_Fail():
    string = "failData"
    signString = test_signStr_Success()
    try:
        DID.verifyString(string, signString, DIDSAMPLE.ROLE['holder']['publicKey'])
        assert True
    except Exception:
        assert False

def test_verifyStr_Key_Fail():
    string = "test"
    signString = test_signStr_Success()
    try:
        DID.verifyString(string, signString, DIDSAMPLE.ROLE['issuer']['publicKey'])
        assert True
    except Exception:
        assert False