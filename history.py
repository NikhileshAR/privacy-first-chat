import json
import os

HIST_DIR = "history"
os.makedirs(HIST_DIR, exist_ok=True)


def _path(peer):
    return os.path.join(HIST_DIR, f"{peer}.json")


def save(peer, entry):
    msgs = []
    if os.path.exists(_path(peer)):
        msgs = json.load(open(_path(peer)))
    msgs.append(entry)
    json.dump(msgs, open(_path(peer), "w"))


def load(peer=None):
    out = []
    for f in os.listdir(HIST_DIR):
        if peer and not f.startswith(peer):
            continue
        out += json.load(open(os.path.join(HIST_DIR, f)))
    return out
