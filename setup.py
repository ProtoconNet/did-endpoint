  
from setuptools import setup, find_packages

setup(
    name             = 'did-endpoint',
    version          = '0.1',
    description      = 'did-endpoint python',
    long_description = open('README.md').read(),
    author           = 'securekim',
    author_email     = 'admin@securekim.com',
    license          = "GPLv3",
    package_dir      = {'':'./src'},
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
