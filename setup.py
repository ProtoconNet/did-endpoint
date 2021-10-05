  
from setuptools import setup, find_packages
with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name             = 'did-endpoint',
    version          = '0.1',
    description      = 'did-endpoint python',
    long_description = long_description,
    long_description_content_type = "text/markdown",
    author           = 'securekim',
    author_email     = 'admin@securekim.com',
    license          = "GPLv3",
    install_requires = [
        'bottle',
        'canister',
        'pyjwt',
        'ed25519',
        'base58',
        'requests',
        'uuid',
        'sentry_sdk',
        'cherrypy',
        'cryptography',
        'image',
        'pytesseract',
        'pytest'
    ],
    packages         = find_packages('./src', exclude=[]),
    keywords         = ['did-endpoint'],
    python_requires  = '>=3.6', 
)
