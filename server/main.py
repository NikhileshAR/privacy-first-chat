import socket
import json

HOST = "0.0.0.0"
PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

clients = {}  # peer_id -> address

print(f"[+] server running on {HOST}:{PORT}")

while True:
    data, addr = sock.recvfrom(65536)

    try:
        pkt = json.loads(data.decode())
    except Exception:
        continue

    if "from" not in pkt:
        continue

    sender = pkt["from"]
    clients[sender] = addr

    target = pkt.get("to")
    if target and target in clients:
        sock.sendto(data, clients[target])
