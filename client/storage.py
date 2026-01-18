import os
import json
from crypto import encrypt, decrypt

KEY_FILE = "client.key"

def load_master_key():
    if not os.path.exists(KEY_FILE):
        key = os.urandom(32)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key
    return open(KEY_FILE, "rb").read()

MASTER_KEY = load_master_key()

def history_path(peer_id):
    return f"history_{peer_id}.enc"

def load_history(peer_id):
    path = history_path(peer_id)
    if not os.path.exists(path):
        return []
    raw = open(path, "rb").read()
    return json.loads(decrypt(MASTER_KEY, raw).decode())

def save_history(peer_id, history):
    raw = json.dumps(history).encode()
    enc = encrypt(MASTER_KEY, raw)
    with open(history_path(peer_id), "wb") as f:
        f.write(enc)
