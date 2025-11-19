# crypto_app.py
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_ITERATIONS = 200000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256-bit key

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password)

def encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    package = salt + nonce + ciphertext
    return base64.b64encode(package).decode()

def decrypt(token: str, password: str) -> str:
    data = base64.b64decode(token)
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ciphertext = data[SALT_SIZE+NONCE_SIZE:]
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
