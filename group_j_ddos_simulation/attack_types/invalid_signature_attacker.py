import time
import uuid
import json
import base64
from scapy.all import IPv6, UDP, Raw, Ether, sendp, get_if_hwaddr

SERVER_IP = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
SRC_PORT = 9999
DST_PORT = 443
INTERFACE = "en0"
TOKEN_FILE = "group_j_ddos_simulation/generated_token_j.json"
NUM_PACKETS = 20

with open(TOKEN_FILE, "r") as f:
    token = json.load(f)

token["Signature"] = base64.b64encode(b"forged_signature").decode()

print("[*] Sending Invalid Signature attack packets...")

for _ in range(NUM_PACKETS):
    nonce = f"is-{uuid.uuid4().hex[:8]}"
    timestamp = int(time.time())

    payload = {
        "PacketToken": "fake",
        "Nonce": nonce,
        "Timestamp": timestamp,
        "Token": token
    }

    pkt = Ether(src=get_if_hwaddr(INTERFACE), dst="ff:ff:ff:ff:ff:ff") / \
        IPv6(dst=SERVER_IP) / \
        UDP(sport=SRC_PORT, dport=DST_PORT) / \
        Raw(load=json.dumps(payload).encode())

    sendp(pkt, iface=INTERFACE, verbose=False)

print("[✓] Invalid Signature attack completed.")