import json
import base64
import time
import uuid
import os
from hashlib import sha256
from scapy.all import IPv6, UDP, Raw, Ether, sendp, get_if_hwaddr

SERVER_IP = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
SRC_PORT = 12345
DST_PORT = 443
TOKEN_FILE = "client_i3/generated_token_i3.json"
IPV6_STORE_FILE = "client_ipv6.json"
INTERFACE = "en0"  

try:
    NUM_PACKETS = int(os.getenv("NUM_PACKETS", 500))
except ValueError:
    NUM_PACKETS = 500

INTERVAL_BETWEEN_PACKETS = 0.005 

with open(TOKEN_FILE, "r") as f:
    token = json.load(f)

with open(IPV6_STORE_FILE, "r") as f:
    client_ip = json.load(f)["client_ip"]

print(f"[*] Starting Group I3 throughput test...")
print(f"    > Sending {NUM_PACKETS} packets from {client_ip}")

for i in range(NUM_PACKETS):
    nonce = f"i3-throughput-{uuid.uuid4().hex[:8]}"
    timestamp = int(time.time())

    packet_token = base64.b64encode(
        sha256(json.dumps(token, sort_keys=True).encode()).digest()
    ).decode()

    payload = {
        "PacketToken": packet_token,
        "Nonce": nonce,
        "Timestamp": timestamp,
        "Token": token
    }

    raw_payload = json.dumps(payload).encode()

    ether = Ether(src=get_if_hwaddr(INTERFACE), dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=raw_payload)

    sendp(pkt, iface=INTERFACE, verbose=False)
    time.sleep(INTERVAL_BETWEEN_PACKETS)

print(f"[✓] Completed sending {NUM_PACKETS} packets.")