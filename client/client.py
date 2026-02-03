import ipaddress
import socket
import json
import threading
import uuid
import time
import sys
from collections import defaultdict

from crypto import gen_keypair, derive_session, encrypt, decrypt

BUFFER = 65536

# ---- server config (CLI) ----
SERVER_HOST = "::1"   # MUST be a real IPv6 address (not ::)
SERVER_PORT = 9999

if len(sys.argv) == 3:
    SERVER_HOST = sys.argv[1].strip("[]")
    SERVER_PORT = int(sys.argv[2])

# ---- hard IPv6 guard ----
if SERVER_HOST == "::":
    raise ValueError("SERVER_HOST cannot be '::' (unspecified IPv6 address)")

try:
    ip = ipaddress.ip_address(SERVER_HOST)
except ValueError:
    raise ValueError("Invalid IPv6 address")

if ip.version != 6:
    raise ValueError("IPv6 ONLY — IPv4 is not allowed")

# ---- identity ----
peer_id = uuid.uuid4().hex[:12]
priv, pub = gen_keypair()

# ---- IPv6 UDP socket (Windows-safe) ----
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

# force pure IPv6 (no v4-mapped)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

# bind locally
sock.bind(("::", 0, 0, 0))

# IMPORTANT: connect() fixes WinError 10051 on Windows
sock.connect((SERVER_HOST, SERVER_PORT, 0, 0))

def send_pkt(pkt):
    sock.send(json.dumps(pkt).encode())

# ---- register (implicit) ----
send_pkt({
    "type": "REGISTER",
    "from": peer_id
})

# ---- state ----
sessions = {}
pending = {}
handshaking = set()
chat_history = defaultdict(list)
lock = threading.Lock()

print(f"[+] connected to server [{SERVER_HOST}]:{SERVER_PORT}")
print(f"[+] your peer_id: {peer_id}")
print('commands: send PEER_ID "msg", history PEER_ID, exit')

def start_handshake(pid):
    if pid in handshaking:
        return
    handshaking.add(pid)
    send_pkt({
        "type": "HELLO",
        "from": peer_id,
        "to": pid,
        "pub": pub.hex()
    })

def send_message(pid, msg):
    with lock:
        if pid in sessions:
            blob = encrypt(sessions[pid], msg).hex()
            send_pkt({
                "type": "MSG",
                "from": peer_id,
                "to": pid,
                "blob": blob
            })
            chat_history[pid].append({
                "ts": time.time(),
                "dir": "out",
                "msg": msg
            })
            print("[+] sent")
        else:
            pending.setdefault(pid, []).append(msg)
            start_handshake(pid)
            print("[i] establishing session and sending…")

def recv_loop():
    while True:
        try:
            data = sock.recv(BUFFER)
        except Exception:
            continue

        try:
            pkt = json.loads(data.decode())
        except Exception:
            continue

        t = pkt.get("type")
        sender = pkt.get("from")
        if not sender:
            continue

        if t == "HELLO":
            peer_pub = bytes.fromhex(pkt["pub"])
            with lock:
                if sender not in sessions:
                    sessions[sender] = derive_session(priv, peer_pub)

            send_pkt({
                "type": "HELLO_ACK",
                "from": peer_id,
                "to": sender,
                "pub": pub.hex()
            })

        elif t == "HELLO_ACK":
            peer_pub = bytes.fromhex(pkt["pub"])
            with lock:
                if sender not in sessions:
                    sessions[sender] = derive_session(priv, peer_pub)
                msgs = pending.pop(sender, [])
                handshaking.discard(sender)

            print(f"[i] session established with {sender}")
            for m in msgs:
                send_message(sender, m)

        elif t == "MSG":
            with lock:
                if sender not in sessions:
                    continue
                msg = decrypt(
                    sessions[sender],
                    bytes.fromhex(pkt["blob"])
                )

            print(f"\n[{sender} → you] {msg}")
            chat_history[sender].append({
                "ts": time.time(),
                "dir": "in",
                "msg": msg
            })

threading.Thread(target=recv_loop, daemon=True).start()

while True:
    try:
        cmd = input("> ").strip()

        if cmd == "exit":
            break

        elif cmd.startswith("send"):
            _, pid, msg = cmd.split(" ", 2)
            send_message(pid, msg.strip('"'))

        elif cmd.startswith("history"):
            parts = cmd.split()
            if len(parts) < 2:
                print("[i] specify peer_id")
                continue

            peer = parts[1]
            if peer not in chat_history:
                print("[i] no history with this peer")
                continue

            print(f"\n--- history with {peer} ---")
            for e in sorted(chat_history[peer], key=lambda x: x["ts"]):
                if e["dir"] == "out":
                    print(f"[you → {peer}] {e['msg']}")
                else:
                    print(f"[{peer} → you] {e['msg']}")

    except KeyboardInterrupt:
        break
