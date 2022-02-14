
<p align="center">
  <h1 align="center">DID-EndPoint</h1>
  <p align="center">
    <a href="">
      <img src="https://img.shields.io/badge/license-GPLv3-blue.svg" />
    </a>
    <a href="https://www.python.org/">
    	<img src="https://img.shields.io/badge/built%20with-Python3-red.svg" />
    </a>
  </p>
</p>

Tooling that automates your Decentralized-Identifier interactions to process DID Auth and VC issuance with holder on Issuer & Verifier implemented in Python.

## Identities

An identity is really just someone or something that can sign data or transactions and also receive signed data about itself.

An identity has:

- An Identifier in the form of a Decentralized ID (DID)

- A signing key

- A public key stored on the mitum

![Mitum Simulation](https://user-images.githubusercontent.com/35220663/141648188-c95a7a4c-c7d7-4697-8bf1-517095cedeb4.gif)

## Installation

```sh
$ python3 setup.py install
```

If setup.py doesn't work properly, please just install necessary packages with requirements.txt before running setup.py.

```sh
pip3 install --upgrade pip

pip3 install -r requirements.txt
```

<b>[optional]</b> If you have a sentry account, Create a new file (privates.py) in the src/configs if it does not exist.

```py
#src/configs/privates.py

LOG = {
    'sentryURL' : "https://{}@{}.ingest.sentry.io/{}",
}
```

## Prework

You should change host to your domain.

src/config/samples.py
```py
"issuer" :{
	...
	"host":"mitum.securekim.com", # change it
	...
"verifier" :{
	...
	"host":"mitum.securekim.com", # change it
```

## Run

```sh

$ python3 src/issuer.py&
$ python3 src/verifier.py&

```

## Postwork
Auto update and refresh for issuer & verifier servers with crontab 
(everyday at 3AM)

```sh
$ crontab -e
	...
	0 3 * * * {Your directory}/did-endpoint/update.sh
```

## TEST

Pre : Run Issuer & Verifier.

For Unit Testing with Local & Network : 
```sh
$ pytest 

```

For Client Testing with Issuer & Verifier : 
```sh
$ python3 holder.py
```
