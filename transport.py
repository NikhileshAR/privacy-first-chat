import requests

def send(server, msg):
    requests.post(f"{server}/send", json=msg)

def poll(server, identity):
    r = requests.get(f"{server}/poll", params={"identity": identity})
    return r.json()["messages"]
