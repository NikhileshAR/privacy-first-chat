# storage.py

_messages = {}

def store_message(identity, msg):
    if identity not in _messages:
        _messages[identity] = []
    _messages[identity].append(msg)

def fetch_messages(identity):
    msgs = _messages.get(identity, [])
    _messages[identity] = []
    return msgs
