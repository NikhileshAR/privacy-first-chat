import socket, json

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9999))

clients = {}

print("[+] server running on :9999")

while True:
    data, addr = sock.recvfrom(65536)
    pkt = json.loads(data.decode())

    sender = pkt["from"]
    clients[sender] = addr   # REGISTER or any packet updates address

    target = pkt.get("to")
    if target and target in clients:
        sock.sendto(data, clients[target])
