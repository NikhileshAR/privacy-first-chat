import socket, json, threading, uuid, time
from crypto import gen_keypair, derive_session, encrypt, decrypt
from collections import defaultdict

SERVER = ("127.0.0.1", 9999)
BUFFER = 65536

peer_id = uuid.uuid4().hex[:12]
priv, pub = gen_keypair()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 0))

def send_pkt(pkt):
    sock.sendto(json.dumps(pkt).encode(), SERVER)

# register
send_pkt({
    "type": "REGISTER",
    "from": peer_id
})

sessions = {}            
pending = {}             
handshaking = set()
chat_history = defaultdict(list)  
lock = threading.Lock()

print(f"[+] your peer_id: {peer_id}")
print('commands: send PEER_ID "msg", history [PEER_ID], exit')

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
            data, _ = sock.recvfrom(BUFFER)
        except ConnectionResetError:
            continue

        pkt = json.loads(data.decode())
        t = pkt["type"]
        sender = pkt["from"]

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
                msg = decrypt(sessions[sender], bytes.fromhex(pkt["blob"]))

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
            if len(parts) == 1:
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

