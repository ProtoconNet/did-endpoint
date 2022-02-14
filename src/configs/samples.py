import datetime

def getTime():
    return str(datetime.datetime.utcnow().isoformat())

#times : days=10
def addTime(addDay):
    now = datetime.datetime.now()
    now += datetime.timedelta(days=addDay)
    myDate = now.isoformat()
    return str(myDate)
    

ROLE = {
    "issuer" :{
        "did" :"did:mtm:testIssuer",
        "privateKey" : "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ",
        "privateKey_SSH" : "TODO",
        "publicKey" : "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "secret" : "ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd",
        "host" : "mtm.securekim.com", #change it
        "port" : 3333,
        "challenge" : "_THISISHARDCODEDCHALLENGEFORTEST",
        "urls" : {
            "didAuth" : "/didAuth",
            "getCredentialProposal" : "/credentialProposal",
            "getCredentialRequest" : "/credentialRequest",
            "getAckMessage" : "/ackMessage",
            "postBuyProtoconPass" : "/buyProtoconPass"
        }
    },
    "holder" : {
        "did" : "did:mtm:testHolder",
        "privateKey" : "4CtnviPnQX6CyHajqyEik8RZpxTx1mJHRhgNJ2uCTVA4",
        "publicKey" : "BY4xsAjAhfhFQpak5W99epnX5NQXd3WK9rWMYKrRYvw4",
        "credentialSubject" : { 
            'driverLicense' : {'name':'Audrey','birth': '2000/01/02','driverLicense': '13-10-662761-82'},
            'protoconPass' : {'startDate':'2021-09-25T00:00:00.000', 'day':5, 'passType':'RestaurantOnly'}
        }
    },
    "verifier" :{
        "host" : "mtm.securekim.com", #change it
        "port" : 3082,
        "secret" : "securekim",
        "webPort" : 8080,
        "challenge" : "THISISHARDCODEDCHALLENGEFORTEST_",
        "urls" : {
            "didAuth" : "/didAuth",
            "getPresentationProposal" : "/presentationProposal",
            "postPresentationProof" : "/presentationProof",
            "getAckMessage" : "/ackMessage"
        }
    },
    "platform" :{
        'url' : 'http://mitum.securekim.com:8888',
        "urls" :{
            "schema" : "http://mitum.securekim.com:8888/v1/schema",
            "resolver" : "https://did-resolver.mitum.com/ddo/",
            "document" : "http://mitum.securekim.com:8888/v1/DIDDocument",
            "createSchema" : "http://mitum.securekim.com:8888/v1/schema",
            "createDefinition" : "http://mitum.securekim.com:8888/v1/credential_definition"

        }
    }
}

_SCHEMA = {
    "schemaID1" : { # schemaID
        "schemaName" : "driverLicense",
        "version" : "0.1",
        "attribute" : ["name", "birth", "driverLicense"]
    },
    "schemaID2" : { # schemaID
        "schemaName" : "protoconPass",
        "version" : "0.1",
        "attribute" : ["startDate", "day", "passType"]
    }
}

_CREDENTIALDEFINITION = {
    "credentialDefinitionID1" : { # schemaID
        "schemaId" : "schemaID1", 
        "tag" : "driverLicense", 
        "revocation" : False
    },
    "credentialDefinitionID2" : { # schemaID
        "schemaId" : "schemaID2", 
        "tag" : "protoconPass", 
        "revocation" : False
    }
}

_PRESENTATION_REQEUST= {
    "requestAttribute" : [
        {
            "name" : "driverLicense",
            "restrictions" : {
                "schemaId" : "schemaID1",
                "credDefId" : "credentialDefinitionID1"
            },
            "concealable" : True
        }, 
        {
            "name" : "protoconPass",
            "restrictions" : {
                "schemaId" : "schemaID2",
                "credDefId" : "credentialDefinitionID2"
            },
            "concealable" : True
        }
    ],
    "predicateAttribute" : [{
        "name":"NONE",
        "condition" : "ZKP CONDITION",
        "value" : "VALUE FOR ZKP",
        "restrictions" : {
            "schemaId" : "schemaID2",
            "credDefId" : "credentialDefinitionID2"
        }
    }],
    "selfAttestedAttribute": [{
        "name" : "NOT VERIFIED"
    }]
}

_VCSCHEMA ={
    "driverLicense" : "vc1",
    "protoconPass" : "vc2"
}

_VCTYPE ={
    "vc1" : "DriverCredential",
    "vc2" : "ProtoconPassCredential"
}

_VPSCHEMA ={
    "rentCar" : "vp1",
}

_BUY_SAMPLE = dict()

def getDIDDocumentURL(did):
    return ROLE["platform"]["urls"]["document"]+"?did="+did

def getVCType(schemaID):
    return _VCTYPE[schemaID]

def getVCSchema(schema):
    return _VCSCHEMA[schema]

def getVCSchemaJSON(schemaID):
    issuerURL = "http://" + ROLE['issuer']['host'] + ":" + str(ROLE['issuer']['port'])
    json = {
        "schema": ROLE['platform']['urls']['schema']+"?id="+schemaID,
        "VCPost": issuerURL+"/" + schemaID,
        "VCGet" : issuerURL+"/" + schemaID
    }
    return json

def getVPSchema(schema):
    return _VPSCHEMA[schema]

def getVPSchemaJSON(schemaID):
    verifierURL = "http://" + ROLE['verifier']['host'] + ":" + str(ROLE['verifier']['port'])
    json = {
        "schema": ROLE['platform']['urls']['schema']+"?id="+schemaID,
        "VPPost": verifierURL+"/" + schemaID,
        "VPGet" : verifierURL+"/" + schemaID
    }
    return json

#role : "holder" / "issuer"
#type : "Ed25519VerificationKey2018" / "RsaSignature2018"
def makeSampleDIDDocument(role, algorithm):
    did = ROLE[role]['did']
    pubkey = ROLE[role]['publicKey']
    didDocument = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id" : did,
        "authentication":[
            {
                "id" : did+"#z"+did[:8],
                "type" : algorithm,
                "controller" : did,
                "publicKeyMultibase" : "z"+did[:8]
            }
        ],
        "verificationMethod" : [
            {
                "id" : did,
                "type" : algorithm,
                "controller" : did,
                "publicKeyBase58" : pubkey
            }
        ]
    }
    return didDocument

def makeSampleVCwithoutJWS(issuer_did, vcType, credentialSubject):
    vc = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": " http://mitum.secureKim.com/credentials/3732 ",
        "type": ["VerifiableCredential", vcType],
        "issuer": issuer_did,
        "issuanceDate": getTime(),
        "expirationDate": addTime(365),
        "credentialSubject": credentialSubject,
        "proof": {
            "type": "Ed25519Signature2018",
            "created": getTime(),
            "proofPurpose": "assertionMethod", 
            "verificationMethod": "https://secureKim.com/issuers/keys/1"
        }
    }
    return vc

def makeSampleVPwithoutJWS(holder_did, vcArr):
    vp = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": holder_did,
        "type": [
            "VerifiablePresentation"
        ],
        "verifiableCredential": vcArr,
        "proof": [{
            "type": "Ed25519Signature2018",
            "expire": addTime(365),
            "created": getTime(),
            "proofPurpose": "authentication",
            "verificationMethod": holder_did
            }]
    }
    return vp

def saveBuySample(uuid, contents):
    try:
        _BUY_SAMPLE[uuid] = contents
        return True
    except Exception:
        return False

def loadBuySample(uuid):
    try:
        return _BUY_SAMPLE[uuid]
    except Exception:
        return False
