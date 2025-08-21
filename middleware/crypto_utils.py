import os, base64, hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- RSA utilities (user keypairs) ---

def make_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key_pem(private_key, path: str, password: Optional[bytes] = None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    with open(path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        ))

def save_public_key_pem(public_key, path: str):
    with open(path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key_pem(path: str, password: Optional[bytes] = None):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def load_public_key_pem(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def rsa_encrypt(pub, data: bytes) -> bytes:
    return pub.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(priv, data: bytes) -> bytes:
    return priv.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# --- AES-GCM utilities ---

def aes_encrypt(plaintext: bytes, key: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return key, nonce, ciphertext

def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)

# --- Hashing ---

def sha256b(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()

def sha256hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()

# --- small helpers ---
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())
