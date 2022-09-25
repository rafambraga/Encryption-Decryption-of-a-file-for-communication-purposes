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


# _____________ Encrypting Key with KU_b

text = key

fname = 'key.pem' 
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
    
pad = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()), 
    salt_length=padding.PSS.MAX_LENGTH
    )

print ("The digested data: " , digest)














