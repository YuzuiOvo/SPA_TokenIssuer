import time
import uuid
import json
import base64
from hashlib import sha256
from scapy.all import IPv6, UDP, Raw, Ether, sendp, get_if_hwaddr

SERVER_IP = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
FAKE_IP = "2001:db8::dead:beef"
SRC_PORT = 9999
DST_PORT = 443
INTERFACE = "en0"
TOKEN_FILE = "group_j_ddos_simulation/generated_token_j.json"
NUM_PACKETS = 20

with open(TOKEN_FILE, "r") as f:
    token = json.load(f)

print("[*] Sending IP Mismatch attack packets...")

for _ in range(NUM_PACKETS):
    nonce = f"im-{uuid.uuid4().hex[:8]}"
    timestamp = int(time.time())

    payload = {
        "PacketToken": base64.b64encode(
            sha256(json.dumps(token, sort_keys=True).encode()).digest()
        ).decode(),
        "Nonce": nonce,
        "Timestamp": timestamp,
        "Token": token
    }

    pkt = Ether(src=get_if_hwaddr(INTERFACE), dst="ff:ff:ff:ff:ff:ff") / \
        IPv6(src=FAKE_IP, dst=SERVER_IP) / \
        UDP(sport=SRC_PORT, dport=DST_PORT) / \
        Raw(load=json.dumps(payload).encode())

    sendp(pkt, iface=INTERFACE, verbose=False)

print("[✓] IP Mismatch attack completed.")