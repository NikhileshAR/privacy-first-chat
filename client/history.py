import json
import os

HIST_DIR = "history"
os.makedirs(HIST_DIR, exist_ok=True)


def _path(peer):
    return os.path.join(HIST_DIR, f"{peer}.json")


def save(peer, entry):
    msgs = []
    if os.path.exists(_path(peer)):
        with open(_path(peer), "r") as f:
            msgs = json.load(f)

    msgs.append(entry)

    with open(_path(peer), "w") as f:
        json.dump(msgs, f)


def load(peer=None):
    out = []
    for fname in os.listdir(HIST_DIR):
        if peer and not fname.startswith(peer):
            continue
        with open(os.path.join(HIST_DIR, fname), "r") as f:
            out.extend(json.load(f))
    return out
