import hmac
import hashlib
import os
from itertools import izip
from Crypto.Cipher import AES

AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 16
SIG_SIZE = hashlib.sha256().digest_size


def __validate_key(key):
    # Make sure key has the correct number of bytes
    size = AES_KEY_SIZE + SIG_SIZE
    key_len = len(key)
    assert (key_len == size), 'Key size wrong. Key is: ' + str(key_len) + ', should be: ' + str(size)


def __key_split(key):
    # Split the key so part of it is used for encrypt/decrypt
    # and other part for signing
    crypt_key = key[:-SIG_SIZE]
    sig_key = key[-SIG_SIZE:]
    return crypt_key, sig_key


def __hmac(key, input):
    mac = hmac.new(key, input, hashlib.sha256)
    return mac.digest()


def __compare(x, y):
    # Compare using xor to mitigate timing attacks
    diff = 0
    for a, b in izip(x, y):
        diff |= ord(a) ^ ord(b)
    return 0 == diff


def encrypt(plaintext, key):
    # Validate key input
    __validate_key(key)
    # Divide up key between crypt and sig
    crypt_key, sig_key = __key_split(key)
    # Pad to AES block size (128 bits)
    pad = AES_BLOCK_SIZE - len(plaintext) % AES_BLOCK_SIZE
    plaintext = plaintext + pad * chr(pad)
    # Generate Initialization Vector
    iv = os.urandom(AES_BLOCK_SIZE)
    # Create the cipher object
    cipher = AES.new(crypt_key, AES.MODE_CBC, iv)
    # Encrypt
    ciphertext = iv + cipher.encrypt(plaintext)
    # Sign the ciphertext with a HMAC
    signature = __hmac(sig_key, ciphertext)
    # Return the concat
    return (ciphertext + signature)


def decrypt(ciphertext, key):
    # Validate key input
    __validate_key(key)
    # Divide up key between crypt and sig
    crypt_key, sig_key = __key_split(key)
    # Separate sigature from rest of ciphertext
    sig = ciphertext[-SIG_SIZE:]
    data = ciphertext[:-SIG_SIZE]
    # Check signature and abort if it's wrong
    mac = __hmac(sig_key, data)
    assert __compare(mac, sig), "Authentication of ciphertext failed."
    # Separate Initialization Vector and cipher data
    iv = data[:AES_BLOCK_SIZE]
    ciphertext = data[AES_BLOCK_SIZE:]
    # Create the cipher
    cipher = AES.new(crypt_key, AES.MODE_CBC, iv)
    # Decrypt
    plaintext = cipher.decrypt(ciphertext)
    # Remove padding
    plaintext = plaintext[:-ord(plaintext[len(plaintext) - 1:])]
    return plaintext