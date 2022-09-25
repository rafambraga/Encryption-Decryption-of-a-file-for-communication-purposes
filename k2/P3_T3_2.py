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
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.asymmetric import utils
from cryptography import x509

# _______________ Verifying Signature

backend = default_backend()
blocksize = 16
data = bytearray(16)
totalsize = 0

myhash = hashes.SHA256()
hasher = hashes.Hash(myhash, backend)

pad = padding.PKCS1v15()

#password = 'hello'

# ______________ Recreating Digest

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

# ______________ Opening Certificates

with open('user1_cert.pem', 'rb') as file:
    certificate = x509.load_pem_x509_certificate(
        data=file.read(),
        backend = backend)
    
public_key = certificate.public_key()
    
sig = open('sign.sig', 'r')
sign = ""
for line in sig:
    if line.startswith('-')==False:
        sign += line
               
print(sign)
sign = base64_decode(sign.encode("utf-8"))

#___________________

try: 
    public_key.verify(
        signature=sign[0],
        data=digest,
        padding=pad,
        algorithm = utils.Prehashed(myhash))
    
    print("The signature was verified.")
    
    # _________________ Decrypt secret key using user's 2 private key
    
    password = 'hello2'
    
    with open('kr2.pem', 'rb') as file1:
        private_key = serialization.load_pem_private_key(
        data = file1.read(), 
        password = password.encode(), 
        backend = backend)
    
    from cryptography.hazmat.primitives.asymmetric import padding
    
    key_ = open('key.pem', 'r')
    key = ""
    for line in key_:
        if line.startswith('-')==False:
            key += line
    
    key = base64_decode(key.encode("utf-8"))
            
    key = private_key.decrypt(
        key[0],
        padding.PKCS1v15()
    )

    print("\n The Key was decrypted")
    
    
    iv_ = open('iv.pem', 'r')
    iv = ""
    for line in iv_:
        if line.startswith('-')==False:
            iv += line
    
    iv = base64_decode(iv.encode("utf-8"))
            
    iv = private_key.decrypt(
        iv[0],
        padding.PKCS1v15()
    )

    print("\n The IV was decrypted")
    
    
    # _____________________ Decrypting file using secret key
    
    cipher = Cipher(
    algorithm=algorithms.AES(key),
    mode=modes.CBC(iv),
    backend=backend)
    
    # set the blocksize 
    blocksize = 16
    
    data2 = bytearray(blocksize)
    # open the files, in buffered binary mode 
    file3 = open('outfile.txt', 'rb')
    file4 = open('decrypted', 'wb')
    
    totalsize2 = 0
    
    from cryptography.hazmat.primitives import padding
    
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    
    # loop until done 
    while True:
        
        # read block from source file 
        num2 = file3.readinto(data2)
        
        # adjust totalsize 
        totalsize2 += num2
    
        # check if full block read 
        if num2 == blocksize:
            plaintext = decryptor.update(data2)
            mydata_pad2 = unpadder.update(plaintext)
            file4.write(mydata_pad2)
        
        else:
            plaintext = decryptor.finalize()
            mydata_pad2 = unpadder.finalize()
            file4.write(mydata_pad2)
            break
        
    # close files (note will also flush destination file 
    file3.close() 
    file4.close()
    
    print("\n File was decrypted")
    
except TypeError:
    print("SIGNATURE NOT VERIFIED")    


# ______________________________ 


      

 
