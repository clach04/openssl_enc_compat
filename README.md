# openssl_enc_compat

Pure Python 2.7 and 3.x library that is compatible with OpenSSL 1.1.1+ encryption and decryption

This is intended to be used a library, rather than as a command line tool. Also checkout:

  * https://github.com/The-Crocop/pyaes256 - lots of dependencies but a nice API but limited to utf-8 data
  * https://github.com/EbryxLabs/opencrypt - Python 3 only with a filename only API (and command line tools)
  * https://github.com/Madhava-mng/openssltool - Python 3 only wapper around openssl command line tool

## Sample

    from openssl_enc_compat.cipher import OpenSslEncDecCompat

    # echo hello| openssl enc -e aes-256-cbc -salt -pbkdf2 -iter 10000 -in - -base64 -out - -pass pass:password
    openssl_crypted_base64_text = 'U2FsdGVkX18NXhFhTlAyvM2jXPu+hhsT344TvO0yLYk='  # base64
    openssl_crypted_base64_text = b'Salted__\r^\x11aNP2\xbc\xcd\xa3\\\xfb\xbe\x86\x1b\x13\xdf\x8e\x13\xbc\xed2-\x89'  # raw binary
    password = b'password'

    print('openssl_crypted_base64_text: %r' % openssl_crypted_base64_text)
    print('password: %r' % password)

    cipher = OpenSslEncDecCompat(password)  # guess/default
    plaintext = cipher.decrypt(openssl_crypted_base64_text)  # guesses if base64 encoded or note
    print('plaintext: %r' % plaintext)

Quick demo:

    python -m openssl_enc_compat.cipher
