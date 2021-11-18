import ed25519
import base64
import base58
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import sys, os
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from tools import did as DID
from configs import samples as DIDSAMPLE

sk,vk = ed25519.create_keypair(entropy=os.urandom)
vk = sk.get_verifying_key()
base58.b58encode(vk.vk_s)

## 방법 : sk 에서 뒤쪽 반 짤라서 버린걸 base58 돌리면 개인키됨
## 공개키는 base58.b58encode(vk.vk_s)

privateKeyB58 = "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ"
privateKeyHex = '34a30441507a5c0d38e12cc8d98771b2f5384ea33d42ef96c49805aee021f4b0' #  base58.b58decode(privateKeyB58).hex()
privateKeyB64 = 'NKMEQVB6XA044SzI2YdxsvU4TqM9Qu+WxJgFruAh9LA='# base64.b64encode(base58.b58decode(privateKeyB58))

# TESTED
privatekeyOBJ = Ed25519PrivateKey.from_private_bytes(base58.b58decode(privateKeyB58))
privatekeyPEM = privatekeyOBJ.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()) 
#OR

# DO NOT USE THIS : PEM FORMAT / pyjwt NOT WORKING WITH OPENSSH-PEM : https://github.com/jpadilla/pyjwt/blob/a629ecd73221f12402066ccc4a13f04a7c856792/jwt/algorithms.py#L537
# if "-----BEGIN PUBLIC" in str_key:
#     return load_pem_public_key(key)
# if "-----BEGIN PRIVATE" in str_key:
#     return load_pem_private_key(key, password=None)
# if str_key[0:4] == "ssh-":
#     return load_ssh_public_key(key)

#privatekeyPEM = privatekeyOBJ.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.OpenSSH, encryption_algorithm=NoEncryption())
#
publicKeyB58 = "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp"
publicKeyOBJ = Ed25519PublicKey.from_public_bytes(base58.b58decode(publicKeyB58))

# TESTED # b'ssh-ed25519 AAA...
publickeySSH = publicKeyOBJ.public_bytes(encoding=Encoding.OpenSSH, format=PublicFormat.OpenSSH) 
#OR
# TESTED
publickeyPEM = publicKeyOBJ.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo) 


#### EXAMPLE : https://gist.github.com/kousu/f3174af57e1fc42a0a88586b5a5ffdc9
priv="""
    2a:c3:a8:78:97:8b:39:80:1d:06:05:9f:05:fa:74:
    4f:ea:3f:c2:9b:97:12:97:60:4b:9c:99:56:53:6c:
    cc:32
    """
pub="""
    fc:32:1b:82:51:a9:c7:80:61:5b:ec:85:57:7a:bc:
    03:bc:60:9a:b2:12:d1:0b:4f:53:50:01:50:ca:6c:
    f9:43
"""
priv = [int(b,16) for b in priv.strip().split(":")]
priv = bytes(priv)
priv = base64.b64encode(priv) # b'KsOoeJeLOYAdBgWfBfp0T+o/wpuXEpdgS5yZVlNszDI='
priv = priv.replace(b"+",b"-").replace(b"/",b"_").rstrip(b"=")

privPEM = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICrDqHiXizmAHQYFnwX6dE/qP8KblxKXYEucmVZTbMwy
-----END PRIVATE KEY-----
"""
pubkeyPEM = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA/DIbglGpx4BhW+yFV3q8A7xgmrIS0QtPU1ABUMps+UM=
-----END PUBLIC KEY-----
"""


sampleBody = {"key":"value"}
try:
    jwtstr = jwt.encode(sampleBody, privatekeyPEM, algorithm="EdDSA")
    decoded = jwt.decode(jwtstr, publickeyPEM, algorithms="EdDSA")
except Exception as ex:
    print(ex)
print(jwtstr)
print(decoded)

######################### VC _ VP TEST ######################

## MAKE VP
vcArr = [{"VC1KEY":"VC1VALUES"}, {"VC2KEY":"VC2VALUES"}]
vp = DIDSAMPLE.makeSampleVPwithoutJWS("did:mtm:ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd", vcArr)
vpJWS = DID.makeJWS_jwtlib(vp, privateKeyB58)
vp['proof'][0]["jws"] = vpJWS

#'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiZGlkOm10bTpFeHNOS2h2RjNwcXdEdkZhVmFpUW5XV2R5ZVZ3eGQiLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlt7IlZDMUtFWSI6IlZDMVZBTFVFUyJ9LHsiVkMyS0VZIjoiVkMyVkFMVUVTIn1dLCJwcm9vZiI6W3sidHlwZSI6IkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiZXhwaXJlIjoiMjAyMS0wNy0yNFQxOTozNDoyOC41MTgwMTMiLCJjcmVhdGVkIjoiMjAyMS0wNy0yNFQxOTozNDoyOC41MTgwMjIiLCJwcm9vZlB1cnBvc2UiOiJhdXRoZW50aWNhdGlvbiIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDptdG06RXhzTktodkYzcHF3RHZGYVZhaVFuV1dkeWVWd3hkIn1dfQ.CbcQHUlOag61EupH5XGxq-GxE-HVKA-fhWriJDgzoBI6DBIhDnigH5pEf5GT-YPjpl2l565Z27JUVovsueGSDA'


## VERIFY VP
#DID.verifyVP(vp, publicKeyB58)


privateKeyB58_2 = "4CtnviPnQX6CyHajqyEik8RZpxTx1mJHRhgNJ2uCTVA4"
publicKeyB58_2 =  "BY4xsAjAhfhFQpak5W99epnX5NQXd3WK9rWMYKrRYvw4"

vcArr = [{"VC1KEY":"VC1VALUES"}, {"VC2KEY":"VC2VALUES"}]
vp = DIDSAMPLE.makeSampleVPwithoutJWS("did:mtm:ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd", vcArr)
vpJWS = DID.makeJWS_jwtlib(vp, privateKeyB58_2)
vp['proof'][0]["jws"] = vpJWS
DID.verifyVP(vp, publicKeyB58_2)