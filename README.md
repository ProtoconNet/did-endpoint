
<p align="center">
<!--   <img src="https://user-images.githubusercontent.com/35220663/126043566-b10938fb-bbf3-4f3a-8e7c-1241841b86fd.png" width="300"> -->
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

Tooling that automates your Decentralized-Identifier interactions to process DID Auth and VC issuance with holder on Issuer implemented in Python.

## Identities

An identity is really just someone or something that can sign data or transactions and also receive signed data about itself.

An identity has:

- An Identifier in the form of a Decentralized ID (DID)

- A signing key

- A public key stored on the mitum

![requestFlow](https://user-images.githubusercontent.com/35220663/126044686-9662f46a-dc37-4623-b123-ca3bd771eaae.png)

## Installation

```sh
python setup.py install
```

If setup.py doesn't work properly, please just install necessary packages with requirements.txt before running setup.py.

```sh
pip install --upgrade pip

pip install -r requirements.txt
```

<b>[optional]</b> If you have a sentry account, Create a new file (privates.py) in the src/configs if it does not exist.

```py
#src/configs/privates.py

LOG = {
    'sentryURL' : "https://{}@{}.ingest.sentry.io/{}",
}
```

## Run

```sh
cd src

python issuer.py &
```

## TEST

```sh
cd test

python holder.py
```

