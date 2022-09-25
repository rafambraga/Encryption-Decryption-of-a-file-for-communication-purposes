from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

import datetime

# =============================================================================
# # ____________________ Generating and saving the RSA Public and Private Key
# backend = default_backend()
# 
# private_key = rsa.generate_private_key(
#         public_exponent = 65537,
#         key_size = 2048,
#         backend = backend)
# 
# public_key = private_key.public_key()
# 
# password = 'hello'
# 
# pem_kr = private_key.private_bytes(
#     encoding = serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))
# 
# pem_ku = public_key.public_bytes(
#     encoding = serialization.Encoding.PEM,
#     format = serialization.PublicFormat.SubjectPublicKeyInfo)
# 
# print(pem_kr)
# 
# file1 = open('kr.pem', 'wb')
# file1.write(pem_kr)
# file1.close()
# 
# file2 = open('ku.pem', 'wb')
# file2.write(pem_ku)
# file2.close()
# 
# with open('kr.pem', 'rb') as file1:
#     private_key = serialization.load_pem_private_key(
#         data = file1.read(), 
#         password = password.encode(), 
#         backend = backend)
# 
# with open('ku.pem', 'rb') as file2:
#     public_key = serialization.load_pem_public_key(
#         data = file2.read(), 
#         backend = backend)
# =============================================================================

# _____________________ Loading Keys

backend = default_backend()
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
    
# _____________________ Create the subject and issuer of the certificate as the same person    
    
subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coral Gables"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Miami"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ECE Depti"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"User 1"),])
    

# ______________________ Create a Certificate builder object

builder = x509.CertificateBuilder()

# ______________________ Set the subject and issuer

builder = builder.subject_name(subject)
builder = builder.issuer_name(issuer)

# ______________________ Set the date

builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
builder = builder.not_valid_after(datetime.datetime(2022, 8, 2))

# ______________________ Set a random serial number

builder = builder.serial_number(x509.random_serial_number())

# ______________________ Add the public key

builder = builder.public_key(public_key)

# ______________________ Add the basic extensions

builder = builder.add_extension(
x509.BasicConstraints(ca=False, path_length=None), critical=True,)
    
# ______________________ Sign the certificate

certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
    backend=default_backend())

# ______________________ Save the certificate
cert_name = 'user1_cert.pem'
with open(cert_name, 'wb') as file:
    file.write(certificate.public_bytes(serialization.Encoding.PEM))    
             