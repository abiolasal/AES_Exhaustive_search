import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import argparse
import string
import filecmp
from random import randint
from utils_demo import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Setup for Bruteforce attack against randomized AES-128-CTR.')
    parser.add_argument('-n', type=int,
                        help='Effective key length in bytes.', default=3)
    parser.add_argument('-m1', type=str,
                        help='Plaintext1 file input name.', default="files/m1.txt")
    parser.add_argument('-m2', type=str,
                        help='Plaintext2 file input name.', default="files/m2.txt")
    parser.add_argument('-m3', type=str,
                        help='Plaintext3 file input name.', default="files/m3.txt")
    args = parser.parse_args()
    # The input value for brute force attack in bits. 16 bits is equal to 2 bytes.
    length_postfix = args.n * 8
    # Reading plaintexts from files.
    plaintext1 = read_file(fn=args.m1).encode()
    plaintext2 = read_file(fn=args.m2).encode()
    plaintext3 = read_file(fn=args.m3).encode()

    # read in all required files: ciphertexts and nonces
    with open("files/c1.bin", mode='rb') as c:
        c1 = c.read()
    with open("files/c2.bin", mode='rb') as d:
        c2 = d.read()
    with open("files/c3.bin", mode='rb') as e:
        c3 = e.read()
    with open("files/nonce1.bin", mode='rb') as n:
        nonce1 = n.read()
    with open("files/nonce2.bin", mode='rb') as m:
        nonce2 = m.read()
    with open("files/nonce3.bin", mode='rb') as q:
        nonce3 = q.read()

    keyspace = int(0xffffff)  # the total key space to be searched
    # loop over keyspace, decrypt and compare output with given plaintext
    for i in range(keyspace):
        key = bin(2 ** 127 + i)
        print(f'Key attempted: {hex(int(key, 2))}')
        pt1 = decryptor_CTR(c1, nonce1, bitstring_to_bytes(key))
        # compare the output to the corresponding given plaintext
        if pt1 == plaintext1:
            pt2 = decryptor_CTR(c2, nonce2, bitstring_to_bytes(key))
            pt3 = decryptor_CTR(c3, nonce3, bitstring_to_bytes(key))
            if pt2 == plaintext2 and pt3 == plaintext3:
                # print out the found key
                print("Key Found ->", hex(int(key, 2)))
                break  # exit from loop
