# Since Python 3.6 this will be a module in the standard library
# This code is just a simple implementation of the same ideas in both sources

# Python 3.6 Docs: https://docs.python.org/dev/library/secrets.html
# https://hg.python.org/cpython/file/default/Lib/secrets.py

# PEP 506: https://www.python.org/dev/peps/pep-0506
# https://bitbucket.org/sdaprano/secrets/src/3e89097653e70ba6e56a8d81f8c94b87294ddf9a/src/secrets.py

import base64
import binascii
import os


DEFAULT_LENGHT = 32


def token_bytes(nbytes=None):
    if nbytes is None:
        nbytes = DEFAULT_LENGHT
    return os.urandom(nbytes)


def token_hex(nbytes=None):
    return binascii.hexlify(token_bytes(nbytes)).decode('ascii')


def token_url(nbytes=None):
    return base64.urlsafe_b64encode(token_bytes(nbytes)).rstrip(b'=').decode('ascii')
