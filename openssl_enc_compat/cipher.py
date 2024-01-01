#!/usr/bin/env python
# -*- coding: us-ascii -*-
# vim:ts=4:sw=4:softtabstop=4:smarttab:expandtab
"""Pure Python encrypt/descrypt routines with compatability with a (subset) of the command line tool openssl 1.1.0+ enc/dec operations.

I.e. Python 2.7 and Python 3.x code to allow encryption/decryption of files compatible with OpenSSL 1.1.0:

    openssl enc -e aes-256-cbc -salt -pbkdf2 -iter 10000 -in in_file -base64 -out out_file
    openssl dec -d aes-256-cbc -salt -pbkdf2 -iter 10000 -in in_file -base64 -out out_file

    echo hello| openssl enc -e aes-256-cbc -salt -pbkdf2 -iter 10000 -in - -base64 -out - -pass pass:password

NOTE PBKDF2 iteration count of 10,000 is the default in OpenSSL 1.1.0 and is considered too few in 2023.
Older versions of OpenSSL did not support; PBKDF2 (and ergo iterations) and salt and used a much weaker KDF.
"""

import base64
import hashlib
import os
import sys

if os.environ.get('NO_PYCRYPTO'):
    # disable PyCryptodome / PyCrypto via OS environment variable NO_PYCRYPTO
    # i.e. force use of pure python Blowfish
    raise ImportError
# http://www.dlitz.net/software/pycrypto/ - PyCrypto - The Python Cryptography Toolkit
import Crypto  # https://github.com/Legrandin/pycryptodome - PyCryptodome (safer/modern PyCrypto)
from Crypto.Cipher import AES
from Crypto import Random

# TODO fall back to pyaes


# Modes from https://peps.python.org/pep-0272/
MODE_ECB = 1  # Electronic Code Book
MODE_CBC = 2  # Cipher Block Chaining - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_%28CBC%29
MODE_CFB = 3  # Cipher Feedback
MODE_PGP = 4  # OpenPGP Message Format
MODE_OFB = 5  # Output Feedback
MODE_CTR = 6  # Counter - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_%28CTR%29
#MODE_GCM = ?  # Galois/Counter Mode - https://en.wikipedia.org/wiki/Galois/Counter_Mode
#MODE_CCM = ?  # Counter with cipher block chaining message authentication code; counter with CBC-MAC - https://en.wikipedia.org/wiki/CCM_mode

# OWASP 2023 recommendation is authenticated modes GCM and CCM
# Of the formats above OWASP 2023 recommendation is MODE_CTR or MODE_CBC (then authenticate with Encrypt-then-MAC with a seperate key for the MAC)


class BaseOpenSslCompatException(Exception):
    '''Base OpenSSL enc/dec Compat exception'''


class BadPassword(BaseOpenSslCompatException):
    '''Bad password exception'''


class UnsupportedFile(BaseOpenSslCompatException):
    '''File not encrypted/not supported exception'''

def to_bytes(data_in_string, note_encoding='latin1'):
    if isinstance(data_in_string, (bytes, bytearray)):
        return data_in_string  # assume bytes already
    else:
        return data_in_string.encode(note_encoding)
    raise NotImplementedError()


OPENSSL_DEFAULT_ITERATION_COUNT = 10000  # 10,000 == 10K - considered small in 2023
OPENSSL_MAGIC_EXPECTED_PREFIX_STR = 'Salted__'  # for openssl enc -e -salt .....
OPENSSL_MAGIC_EXPECTED_PREFIX = to_bytes(OPENSSL_MAGIC_EXPECTED_PREFIX_STR)  # for openssl enc -e -salt .....
OPENSSL_MAGIC_EXPECTED_PREFIX_BASE64 = to_bytes('U2FsdGVkX1')  # for openssl enc -e -salt -base64 .....

def openssl_pbkdf2(key, salt, iteration_count=OPENSSL_DEFAULT_ITERATION_COUNT):
    """Returns tuple of (aes_key, aes_iv)
    TODO accept None for salt and then generate random
    Currently assumes salt is the correct size (8-bytes)
    """
    # OpenSSL key derivation function is pbkdf2
    # derive/generate AES encryption key 32-bytes (256-bits) and IV 16-bytes (128-bits) from password and salt, total of 48-bytes (384-bits)
    key_plus_iv = hashlib.pbkdf2_hmac('sha256', key, salt, iteration_count, 48)
    #print('DEBUG key_plus_iv %r' % key_plus_iv)

    aes_key = key_plus_iv[0:32]
    aes_iv = key_plus_iv[32:48]

    return aes_key, aes_iv

class OpenSslEncDecCompat:
    """Cipher to handle OpenSSL format encryped data, i.e. OpenSSL 1.1.0 compatible (with a very small subset of options).

    Intended to allow decryption of files generated with OpenSSL 1.1.0 and vice-versa. Supported OpenSSL flags/formats:

        openssl enc -e aes-256-cbc -salt -pbkdf2 -iter 10000 -in in_file -base64 -out out_file
        openssl dec -d aes-256-cbc -salt -pbkdf2 -iter 10000 -in in_file -base64 -out out_file

        echo hello| openssl enc -e aes-256-cbc -salt -pbkdf2 -iter 10000 -in - -base64 -out - -pass pass:password

    NOTE PBKDF2 iteration count of 10,000 is the default in OpenSSL 1.1.0 and is considered too few in 2023.
    Older versions of OpenSSL did not support; PBKDF2 (and ergo iterations) and salt and used a much weaker KDF.

    API PEP-272 Like... This is non-confirming:
      * no new() method, all input controlled via class constructor
      * ONLY decrypt() and encrypt() mechanisms
      * requires bytes (depending on how you read the PEP-272, this may actually be conforming based on datatypes available at the time the spec was finalized)

    Cipher PEP 272 API for Block Encryption Algorithms v1.0 https://www.python.org/dev/peps/pep-0272/

    File format (for raw binary):
        8-bytes - Magic prefix 'Salted__' - when base64 encoded 'U2FsdGVkX1'...
        8-bytes - salt
        X-bytes - encrypted payload, encrypted with key and iv derived from pbkdf2 with 10,000 iterations. This implementation only handles AES-256-CBC
    Nothing in the file indicates encryption nor kdf (iterations). See KeepOut format https://github.com/clach04/openssl_enc_compat/issues/2
    """

    def __init__(self, key, mode=MODE_CBC, IV=None, **kwargs):
        if not isinstance(key, bytes):
            raise NotImplementedError('key must be bytes')
        if mode != MODE_CBC:  # TODO ignore?
            raise NotImplementedError('mode %r not supported' % mode)
        if IV is not None:
            raise NotImplementedError('For now IV can not be static/specified and will be randomly generated')
    
        self.key = key
        self._openssl_options = {}
        # randomly generated salt WILL be used
        # PBKDF2 WILL be used
        self._openssl_options['base64'] = kwargs.get('base64', None)
        self._openssl_options['cipher_name'] = kwargs.get('cipher', 'aes-256-cbc')  # actual name, mode, and size
        self._openssl_options['pbkdf2_iteration_count'] = kwargs.get('iter', OPENSSL_DEFAULT_ITERATION_COUNT)  # pbkdf2 iteration count - 10K is the default as of 2023 since OpenSSL 1.1.0
        # TODO user specificed salt and IV
        # TODO other cipher names
        # TODO clear kwargs of processed arguments, and raise an error if anything else left (i.e. unsupported arguments)

    def decrypt(self, in_bytes):
        base64_encoded = self._openssl_options['base64']
        if base64_encoded is None:
            # heuristic based on content
            required_prefix = OPENSSL_MAGIC_EXPECTED_PREFIX_STR
            if isinstance(in_bytes, (bytes, bytearray)):
                required_prefix = OPENSSL_MAGIC_EXPECTED_PREFIX
            if in_bytes.startswith(required_prefix):
                base64_encoded = False
            else:
                base64_encoded = True
        if base64_encoded:
            in_bytes = base64.b64decode(in_bytes)
        #print('DEBUG in_bytes %r' % in_bytes)
        if not in_bytes.startswith(b'Salted__'):
            raise UnsupportedFile()

        salt = in_bytes[8:16]
        encrypted_bytes = in_bytes[16:]

        aes_key, aes_iv = openssl_pbkdf2(self.key, salt, self._openssl_options['pbkdf2_iteration_count'])
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        plain_bytes = cipher.decrypt(encrypted_bytes)
        #print('DEBUG plain_bytes %r' % plain_bytes)

        # PKCS#7 padding
        last_byte = plain_bytes[-1]
        #print('DEBUG last_byte %r' % last_byte)
        #print('DEBUG last_byte %r' % type(last_byte))
        if not isinstance(last_byte, (int,)):
            last_byte = ord(last_byte)  # for multiple bytes use struct instead
        if last_byte > AES.block_size:
            raise BaseOpenSslCompatException('Invalid PKCS#7 padding %r' % last_byte)
        plain_bytes = plain_bytes[:-last_byte]
        #print('DEBUG plain_bytes %r' % plain_bytes)
        return plain_bytes

    def encrypt(self, in_bytes):
        if not isinstance(in_bytes, bytes):
            raise NotImplementedError('in_bytes must be bytes')
        salt = Random.get_random_bytes(8)
        aes_key, aes_iv = openssl_pbkdf2(self.key, salt, self._openssl_options['pbkdf2_iteration_count'])
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        # PKCS#7 padding
        last_byte = AES.block_size - (len(in_bytes) % AES.block_size)
        in_bytes += bytearray([last_byte] * last_byte)
        encrypted_bytes = cipher.encrypt(in_bytes)
        encrypted_bytes = OPENSSL_MAGIC_EXPECTED_PREFIX + salt + encrypted_bytes
        base64_encoded = self._openssl_options['base64']
        if base64_encoded:
            return base64.b64encode(encrypted_bytes)
        return encrypted_bytes



def main(argv=None):
    if argv is None:
        argv = sys.argv

    print('Python %s on %s\n\n' % (sys.version, sys.platform))
    print('Python %s on %s\n\n' % (sys.version.replace('\n', ' - '), sys.platform))
    print('Python %r on %r\n\n' % (sys.version, sys.platform))

    r"""demo

        echo hello| "C:\Program Files\Git\mingw64\bin\openssl.exe" aes-256-cbc -e -salt -pbkdf2 -iter 10000 -in - -a -out - -pass pass:password
        echo hello| "C:\Program Files\Git\mingw64\bin\openssl.exe" aes-256-cbc -e -salt -pbkdf2 -iter 10000 -in - -base64 -out - -pass pass:password
        U2FsdGVkX18NXhFhTlAyvM2jXPu+hhsT344TvO0yLYk=

    """

    openssl_crypted_base64_text = 'U2FsdGVkX18NXhFhTlAyvM2jXPu+hhsT344TvO0yLYk='  # base64
    openssl_crypted_base64_text = b'Salted__\r^\x11aNP2\xbc\xcd\xa3\\\xfb\xbe\x86\x1b\x13\xdf\x8e\x13\xbc\xed2-\x89'  # raw binary
    #openssl_crypted_base64_text = b'12345678'
    #openssl_crypted_base64_text = '12345678'
    password = b'password'

    print('openssl_crypted_base64_text: %r' % openssl_crypted_base64_text)
    print('password: %r' % password)

    cipher = OpenSslEncDecCompat(password)  # guess/default
    plaintext = cipher.decrypt(openssl_crypted_base64_text)  # guesses if base64 encoded or note
    print('plaintext: %r' % plaintext)


    return 0


if __name__ == "__main__":
    sys.exit(main())
