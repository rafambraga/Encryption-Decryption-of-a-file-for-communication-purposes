from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode 

import os 
import io

import base64

backend = default_backend()

myhash = hashes.SHA256()
hasher = hashes.Hash(myhash, backend)

#print( "Type data: ")

#text = input()
text = "This is a test"

fname = 'p3t2_textfile.txt' 
path = os.path.abspath(fname)
file = open(fname, 'w')
file.write(text)
file.close()

print("The typed text was: ", text)

file = open(fname, 'rb')

data = bytearray(16)
totalsize = 0
blocksize = 16

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
    
pad = padding.PKCS1v15()

print ("The digested data: " , digest)

#_____________________________________________________________________________ 

password = 'hello'

with open('kr.pem', 'rb') as file1:
    private_key = serialization.load_pem_private_key(
        data = file1.read(), 
        password = password.encode(), 
        backend = backend)

with open('ku.pem', 'rb') as file2:
    public_key = serialization.load_pem_public_key(
        data = file2.read(), 
        backend = backend)

## ________________________________________________

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



             