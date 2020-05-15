import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import argparse
from random import randint
from utils import *

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
    #The input value for brute force attack in bits. 16 bits is equal to 2 bytes.
    length_postfix = args.n * 8
    #Reading plaintexts from files. 
    plaintext1 = read_file(fn = args.m1).encode()
    plaintext2 = read_file(fn = args.m2).encode()
    plaintext3 = read_file(fn = args.m3).encode()

    # The last "length_postfix" bits are chosen at random
    postfix_key = randint(0, 2**length_postfix-1)

    #Defining the key for encryption.
    main_key = bin(2 ** 127 + postfix_key)
    write_file(fn = "files/key.bin", value = main_key)
    
    #Encrypting plain-texts.
    nonce1, ctxt1 = encryptor_CTR(message=plaintext1, key=bitstring_to_bytes(main_key))
    write_bytes(fn = "files/c1.bin", value = ctxt1)
    write_bytes(fn = "files/nonce1.bin", value = nonce1)    

    nonce2, ctxt2 = encryptor_CTR(message=plaintext2, key=bitstring_to_bytes(main_key))
    write_bytes(fn = "files/c2.bin", value = ctxt2)
    write_bytes(fn = "files/nonce2.bin", value = nonce2)    

    nonce3, ctxt3 = encryptor_CTR(message=plaintext3, key=bitstring_to_bytes(main_key))
    write_bytes(fn = "files/c3.bin", value = ctxt3)
    write_bytes(fn = "files/nonce3.bin", value = nonce3)    
    