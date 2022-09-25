from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography import x509

backend = default_backend()

blocksize = 16
data = bytearray(16)
totalsize = 0

myhash = hashes.SHA256()
hasher = hashes.Hash(myhash, backend)

with open('user1_cert.pem', 'rb') as file:
    certificate = x509.load_pem_x509_certificate(
    data=file.read(),
    backend=backend)
    
public_key = certificate.public_key()

sig = certificate.signature

data = certificate.tbs_certificate_bytes

hasher.update(data)
digest = hasher.finalize()

pad = padding.PKCS1v15()

try: 
    public_key.verify(
        signature=sig,
        data=digest,
        padding=pad,
        algorithm = utils.Prehashed(myhash))
    
    print("The signature was verified.")

except TypeError:
    print("SIGNATURE NOT VERIFIED")   


