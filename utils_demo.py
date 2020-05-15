import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import argparse
from random import randint


# This is the encryption function. It gets a plaintext a key and returns the ciphertext and nonce.
def encryptor_CTR(message, key, nonce = None):
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(message)    
    nonce = cipher.nonce
    return nonce, ct


# This is the decryption funtion. It gets a ciphertext, a nonce and a key and returns the plaintext.
def decryptor_CTR(ctxt, nonce, key):
    try:
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ctxt)
        return pt
    except ValueError as KeyError:
        return None


# Converting string to bytes.
def string_to_bytes(string_value):
    return bytearray(string_value,
                     encoding='utf-8')


def read_file(fn):
    f = open(fn, "r")
    value = f.read()
    f.close()
    return value

def read_bytes(fn):
    f = open(fn, "rb")
    value = f.read()
    f.close()
    return value

    
def write_file(fn, value):
    f = open(fn, "w")
    f.write(value)
    f.close()

def write_bytes(fn, value):
    f = open(fn, "wb")
    f.write(value)
    f.close()


def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()

    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

