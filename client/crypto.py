from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def gen_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return priv, pub

def derive_session(priv, peer_pub_bytes):
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = priv.exchange(peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session-key",
    ).derive(shared)

def encrypt(key, msg: str) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, msg.encode(), None)
    return nonce + ct

def decrypt(key, blob: bytes) -> str:
    aes = AESGCM(key)
    nonce = blob[:12]
    ct = blob[12:]
    return aes.decrypt(nonce, ct, None).decode()
