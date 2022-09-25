import os 
import io

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode
from encodings.base64_codec import base64_decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509

# _________________________ Encrypt 'infile' with symmetric key

# filenames
fname = 'infile.txt' 
fname2 = 'outfile.txt'
# get the full path names 
path = os.path.abspath(fname) 
path2 = os.path.abspath(fname2)


backend = default_backend()
salt = os.urandom(16)

salt_file_name = 'salt.txt'
path3 = os.path.abspath(salt_file_name)
salt_file = open(salt_file_name, 'wb') 
salt_file.write(salt)
salt_file.close()

print("SALT" , salt.hex())

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend)

idf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend)

passwd = b'password'
ivval = b'hello'

key = kdf.derive(passwd)
iv = idf.derive(ivval)

# print message to user
print('copying ', path, 'to ', path2)

# set the blocksize 
blocksize = 16

# set the totalsize counter 
totalsize = 0

# create a mutable array to hold the bytes 
data = bytearray(blocksize)

print(" \nKey: ", key.hex(), '\n')
print("IV: ", iv.hex(), '\n')

cipher = Cipher(
    algorithm=algorithms.AES(key),
    mode=modes.CBC(iv),
    backend=backend)

encryptor = cipher.encryptor()

# open the files, in buffered binary mode 
file = open(fname, 'rb')
file2 = open(fname2, 'wb')

print("Message to be sent: ", fname, '\n')

padder = padding.PKCS7(128).padder()
# loop until done 
while True:
    
    # read block from source file 
    num = file.readinto(data)
    
    # adjust totalsize 
    totalsize += num
    
    # print data, assuming text data 
    print(num,data)

    # use following if raw binary data 
    # print(num,data.hex())

    # check if full block read 
    if num == blocksize:
    
        mydata_pad = padder.update(data)
        ciphertext = encryptor.update(mydata_pad) 
        print(ciphertext.hex())
        file2.write(ciphertext)
    
    else:
        # extract subarray 
        data2 = data[0:num]
        mydata_pad = padder.update(data2) + padder.finalize()
        ciphertext = encryptor.update(mydata_pad) + encryptor.finalize()
        # write subarray to destination and break loop 
        file2.write(ciphertext)
        break
    
    
# close files (note will also flush destination file 
file.close() 
file2.close()

# ________________ Opening Certificate

from cryptography.hazmat.primitives.asymmetric import padding

with open('user2_cert.pem', 'rb') as file:
    certificate = x509.load_pem_x509_certificate(
        data=file.read(),
        backend = backend)
    
public_key = certificate.public_key()


# ________________ Encrypting Key with KU_b

key_encrypted = public_key.encrypt(
            key,
            padding.PKCS1v15())

key_encrypted = base64_encode(key_encrypted)

file1 = open('key.pem', 'w')
file1.write("-----BEGIN KEY----- \n")
file1.write(key_encrypted[0].decode("UTF-8"))
file1.write("-----END KEY-----")
file1.close()


# ________________ Encrypting IV with KU_b
iv_encrypted = public_key.encrypt(
    iv,
    padding.PKCS1v15())

iv_encrypted = base64_encode(iv_encrypted)
file1 = open('iv.pem', 'w')
file1.write("-----BEGIN IV----- \n")
file1.write(iv_encrypted[0].decode("UTF-8"))
file1.write("-----END IV-----")
file1.close()


# __________________ Message Digest

myhash = hashes.SHA256()
hasher = hashes.Hash(myhash, backend)

file = open('outfile.txt', 'rb')
while True:
    num = file.readinto(data)
    if num == blocksize:
        hasher.update(data)
    else:
        hasher.update(data)
        break
file.close()

file = open('key.pem', 'rb')
while True:
    num = file.readinto(data)
    if num == blocksize:
        hasher.update(data)
    else:
        hasher.update(data)
        break
file.close()

file = open('iv.pem', 'rb')
while True:
    num = file.readinto(data)
    if num == blocksize:
        hasher.update(data)
    else:
        hasher.update(data)
        break
file.close()

digest = hasher.finalize()
print("Digest: \n", digest)

# __________________ Sign Message digest with user 1 private key

password = 'hello'

pad = padding.PKCS1v15()

with open('kr.pem', 'rb') as file1:
    private_key = serialization.load_pem_private_key(
        data = file1.read(), 
        password = password.encode(), 
        backend = backend)

sig = private_key.sign(
    data=digest,
    padding=pad,
    algorithm=utils.Prehashed(myhash))

sig = base64_encode(sig)

file1 = open('sign.sig', 'w')
file1.write("-----BEGIN SIGNATURE----- \n")
file1.write(sig[0].decode("UTF-8"))
file1.write("-----END SIGNATURE-----")
file1.close()














