#!/usr/bin/env python
# -*- coding: us-ascii -*-
# vim:ts=4:sw=4:softtabstop=4:smarttab:expandtab
"""Test suite for OpenSSL enc/dec Compat.

Sample usage:

    python -m openssl_enc_compat.tests.testsuite -v
    python -m openssl_enc_compat.tests.testsuite -v DecryptTest

"""

import os
import pdb
import sys

from io import BytesIO as FakeFile  # py3

try:
    if sys.version_info < (2, 3):
        raise ImportError
    import unittest2
    unittest = unittest2
except ImportError:
    import unittest
    unittest2 = None


import openssl_enc_compat
from openssl_enc_compat.cipher import OpenSslEncDecCompat, OPENSSL_MAGIC_EXPECTED_PREFIX_BASE64, OPENSSL_MAGIC_EXPECTED_PREFIX

is_py3 = sys.version_info >= (3,)
is_win = sys.platform.startswith('win')


class TestUtil(unittest.TestCase):
    def skip(self, reason):
        """Skip current test because of `reason`.

        NOTE currently expects unittest2, and defaults to "pass" if not available.

        unittest2 does NOT work under Python 2.2.
        Could potentially use nose or py.test which has (previously) supported Python 2.2
          * nose http://python-nose.googlecode.com/svn/wiki/NoseWithPython2_2.wiki
          * py.test http://codespeak.net/pipermail/py-dev/2005-February/000203.html
        """
        #self.assertEqual(1, 0)
        if unittest2:
            raise unittest2.SkipTest(reason)
        else:
            raise self.skipTest(reason)  # py3 and 2.7 have this
            """
            print(reason)
            self.fail('SKIP THIS TEST: ' + reason)
            #self.assertTrue(False, reason)
            #raise Exception(reason)
            """
class TestBase(TestUtil):
    pass

class DecryptTest(TestBase):

    password = b'password'
    canon = b'hello'  # newline...

    def test_linux_base64_hello(self):
        # echo hello| openssl enc -e -aes-256-cbc -in - -out - -base64 -salt -pbkdf2 -iter 10000  -pass pass:password
        openssl_crypted_base64 = 'U2FsdGVkX1+PeTa4+Bk6SWEa9ytWl8/Ds0404dxtvcg='  # base64 from Linux: OpenSSL 1.1.1f  31 Mar 2020

        cipher = OpenSslEncDecCompat(self.password)  # guess/default
        plaintext = cipher.decrypt(openssl_crypted_base64)  # guesses if base64 encoded or not
        self.assertEqual(self.canon + b'\n', plaintext)

    def test_linux_binary_hello(self):
        # echo hello| openssl enc -e -aes-256-cbc -in - -out - -salt -pbkdf2 -iter 10000  -pass pass:password
        openssl_crypted_raw = b'Salted__\x8fy6\xb8\xf8\x19:Ia\x1a\xf7+V\x97\xcf\xc3\xb3N4\xe1\xdcm\xbd\xc8'  # base64 from Linux: OpenSSL 1.1.1f  31 Mar 2020

        cipher = OpenSslEncDecCompat(self.password)  # guess/default
        plaintext = cipher.decrypt(openssl_crypted_raw)  # guesses if base64 encoded or not
        self.assertEqual(self.canon + b'\n', plaintext)

    def test_windows_base64_hello(self):
        # echo hello| openssl enc -e aes-256-cbc -salt -pbkdf2 -iter 10000 -in - -base64 -out - -pass pass:password
        openssl_crypted_base64 = 'U2FsdGVkX18NXhFhTlAyvM2jXPu+hhsT344TvO0yLYk='  # base64 from Windows machine OpenSSL 3.1.4 24 Oct 2023 (Library: OpenSSL 3.1.4 24 Oct 2023)

        cipher = OpenSslEncDecCompat(self.password)  # guess/default
        plaintext = cipher.decrypt(openssl_crypted_base64)  # guesses if base64 encoded or not
        self.assertEqual(self.canon + b'\r\n', plaintext)

    def test_windows_binary_hello(self):
        # echo hello| openssl enc -e aes-256-cbc -salt -pbkdf2 -iter 10000 -in - -out - -pass pass:password
        openssl_crypted_raw = b'Salted__\r^\x11aNP2\xbc\xcd\xa3\\\xfb\xbe\x86\x1b\x13\xdf\x8e\x13\xbc\xed2-\x89'  # raw binary from Windows machine OpenSSL 3.1.4 24 Oct 2023 (Library: OpenSSL 3.1.4 24 Oct 2023)

        cipher = OpenSslEncDecCompat(self.password)  # guess/default
        plaintext = cipher.decrypt(openssl_crypted_raw)  # guesses if base64 encoded or not
        self.assertEqual(self.canon + b'\r\n', plaintext)

# TODO negative tests to ensure exceptions are raised
# call with base64 param set to True and False
# test with more interations
# Test with other AES modes
# Implement non-AES ciphers
# Compare behavior with this implementation and openssl with mismatched iter counts;  echo hello| openssl enc -e -aes-256-cbc -in - -out - -base64 -salt -pbkdf2 -iter 10000  -pass pass:password | openssl enc -d -aes-256-cbc -in - -out - -base64 -salt -pbkdf2 -iter 1000  -pass pass:password

class EncryptTest(TestBase):

    password = b'password'
    plain_text = b'hello'

    def test_encrypt_decrypt_binary_explict(self):
        cipher = OpenSslEncDecCompat(self.password, base64=False)
        crypted_bytes = cipher.encrypt(self.plain_text)
        self.assertTrue(crypted_bytes.startswith(OPENSSL_MAGIC_EXPECTED_PREFIX))
        plain_bytes = cipher.decrypt(crypted_bytes)
        self.assertEqual(self.plain_text, plain_bytes)

    def test_encrypt_decrypt_binary_implict(self):
        cipher = OpenSslEncDecCompat(self.password)
        crypted_bytes = cipher.encrypt(self.plain_text)
        self.assertTrue(crypted_bytes.startswith(OPENSSL_MAGIC_EXPECTED_PREFIX))
        plain_bytes = cipher.decrypt(crypted_bytes)  # guesses if base64 encoded or not
        self.assertEqual(self.plain_text, plain_bytes)

    def test_encrypt_decrypt_base64(self):
        cipher = OpenSslEncDecCompat(self.password, base64=True)
        crypted_bytes = cipher.encrypt(self.plain_text)
        self.assertTrue(crypted_bytes.startswith(OPENSSL_MAGIC_EXPECTED_PREFIX_BASE64))
        plain_bytes = cipher.decrypt(crypted_bytes)  # guesses if base64 encoded or not
        self.assertEqual(self.plain_text, plain_bytes)


def debugTestRunner(post_mortem=None):
    """unittest runner doing post mortem debugging on failing tests"""
    if post_mortem is None:
        post_mortem = pdb.post_mortem
    class DebugTestResult(unittest.TextTestResult):
        def addError(self, test, err):
            # called before tearDown()
            traceback.print_exception(*err)
            post_mortem(err[2])
            super(DebugTestResult, self).addError(test, err)
        def addFailure(self, test, err):
            traceback.print_exception(*err)
            post_mortem(err[2])
            super(DebugTestResult, self).addFailure(test, err)
    return unittest.TextTestRunner(resultclass=DebugTestResult)


def main():
    #openssl_enc_compat.print_version_info()
    if os.environ.get('DEBUG_ON_FAIL'):
        unittest.main(testRunner=debugTestRunner())
        ##unittest.main(testRunner=debugTestRunner(pywin.debugger.post_mortem))
        ##unittest.findTestCases(__main__).debug()
    else:
        unittest.main()

if __name__ == '__main__':
    main()
