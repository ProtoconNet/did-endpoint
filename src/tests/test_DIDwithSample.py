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
    print(result)
    assert (result) == False

def test_DIDAuthSuccess():
    challenge = DID.generateChallenge()
    signedChallenge = DID.signString(challenge, DIDSAMPLE.ROLE['holder']['privateKey'])
    verified = DID.verifyString(challenge, signedChallenge, DIDSAMPLE.ROLE['holder']['publicKey'])
    assert verified

def test_DIDAuthFail_StringError():
    challenge = DID.generateChallenge()
    signedChallenge = DID.signString("FAIL_CHALLENGE", DIDSAMPLE.ROLE['holder']['privateKey'])
    verified = DID.verifyString(challenge, signedChallenge, DIDSAMPLE.ROLE['holder']['publicKey'])
    assert verified == False

def test_DIDAuthFail_PrivateKeyError():
    challenge = DID.generateChallenge()
    signedChallenge = DID.signString(challenge, "FAIL_PRIVKEY")
    verified = DID.verifyString(challenge, signedChallenge, DIDSAMPLE.ROLE['holder']['publicKey'])
    assert verified == False

def test_DIDAuthFail_PublicKeyError():
    challenge = DID.generateChallenge()
    signedChallenge = DID.signString(challenge, DIDSAMPLE.ROLE['holder']['privateKey'])
    verified = DID.verifyString(challenge, signedChallenge, "FAIL_PUBKEY")
    assert verified == False

def test_SaveAndLoad_CredentialSubject():
    uuid = DID.genUUID()
    DID.saveCredentialSubject(uuid, {"TEST" : "SUCCESS"})
    load = DID.loadCredentialSubject(uuid)
    assert load["TEST"] == "SUCCESS"

def test_SaveAndLoad_UUIDStatus():
    uuid = DID.genUUID()
    DID.saveUUIDStatus(uuid, "TEST")
    load = DID.loadUUIDStatus(uuid)
    assert load == "TEST"

