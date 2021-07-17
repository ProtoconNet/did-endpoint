import datetime

def getTime():
    return str(datetime.datetime.utcnow().isoformat())

ROLE = {
    "issuer" :{
        "did" :"did:mtm:3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "privateKey" : "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ",
        "publicKey" : "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "secret" : "ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd",
        "url" : "http://127.0.0.1",
        "port" : 3333
    },
    "holder" : {
        "did" : "did:mtm:ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd",
        "privateKey" : "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ",
        "publicKey" : "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "credentialSubject" : {'selfie':'/9j/4AAQSkZJRgABAQAASABIAAD/.....',
        'name':'Gil-dong','amount': 3,'buyAt': getTime()} 
    },
    "verifier" :{

    },
    "platform" :{
        'url' : 'http://mitum.securekim.com:8080',
        "urls" :{
            "scheme" : "http://mitum.securekim.com:8080/v1/scheme",
            "resolver" : "https://did-resolver.mitum.com/ddo/",
            "document" : "http://mitum.securekim.com:8080/v1/DIDDocument"
        }
    }
}

def makeSampleDIDDocument():
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

def makeSampleVC(issuer_did, credentialSubject):
    vc = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": " http://mitum.secureKim.com/credentials/3732 ",
        "type": ["VerifiableCredential", "DriverCredential"],
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