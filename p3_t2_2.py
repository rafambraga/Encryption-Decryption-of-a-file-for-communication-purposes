from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode
from encodings.base64_codec import base64_decode
from cryptography import x509

import os 
import io

import os
import base64

import re

backend = default_backend()
blocksize = 16
data = bytearray(16)
totalsize = 0

myhash = hashes.SHA256()
hasher = hashes.Hash(myhash, backend)

pad = padding.PKCS1v15()

file = open('p3t2_textfile.txt', 'rb')

while True:
    
    # read block from source file 
    num = file.readinto(data)
        
    # print data, assuming text data 
    print(num,data)

    # check if full block read 
    if num == blocksize:
        #print(data)
        hasher.update(data)
    else:
        # extract subarray 
        #print(data[0:num])
        hasher.update(data)
        digest = hasher.finalize()        
        break

password = 'hello'

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

except TypeError:
    print("SIGNATURE NOT VERIFIED")    


 
