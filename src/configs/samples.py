import datetime

def getTime():
    return str(datetime.datetime.utcnow().isoformat())


ROLE = {
    "issuer" :{
        "did" :"did:mtm:3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "privateKey" : "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ",
        "publicKey" : "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "secret" : "ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd",
        "host" : "127.0.0.1",
        "port" : 3333
    },
    "holder" : {
        "did" : "did:mtm:ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd",
        "privateKey" : "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ",
        "publicKey" : "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "credentialSubject" : { 
            'driverLicense' : {'selfie':'/9j/4AAQSkZJRgABAQAASABIAAD/.....','name':'Gil-dong','amount': 3,'buyAt': getTime()},
            'jejuPass' : {'startDate':'2021-09-25T00:00:00.000', 'day':5, 'passType':'RestaurantOnly'}
        }
    },
    "verifier" :{
        "port" : 4444
    },
    "platform" :{
        'url' : 'http://mitum.securekim.com:8080',
        "urls" :{
            "schema" : "http://mitum.securekim.com:8080/v1/schema",
            "resolver" : "https://did-resolver.mitum.com/ddo/",
            "document" : "http://mitum.securekim.com:8080/v1/DIDDocument"
        }
    }
}

_VCSCHEMA ={
    "driverLicense" : "vc1",
    "jejuPass" : "vc2"
}

_VCTYPE ={
    "vc1" : "DriverCredential",
    "vc2" : "JejuPassCredential"
}

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

#role : "holder" / "issuer"
#type : "Ed25519VerificationKey2018" / "RsaSignature2018"
def makeSampleDIDDocument(role, algorithm):
    did = ROLE['holder']['did']
    pubkey = ROLE['holder']['publicKey']
    didDocument = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id" : did,
        "authentication":[
            {
                "id" : did+"#z"+did[:8],
                "type" : "Ed25519VerificationKey2018",
                "controller" : did,
                "publicKeyMultibase" : "z"+did[:8]
            }
        ],
        "verificationMethod" : [
            {
                "id" : did,
                "type" : "Ed25519VerificationKey2018",
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
        "proof": [
            {
            "type": "Ed25519Signature2018",
            "expire": getTime(),
            "created": getTime(),
            "proofPurpose": "authentication",
            "verificationMethod": holder_did
            }
        ]
    }
    return vp
