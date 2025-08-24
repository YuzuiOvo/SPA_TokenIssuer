import json
import base64
import time
import uuid
from hashlib import sha256
from scapy.all import IPv6, UDP, Raw, Ether, sendp, get_if_hwaddr

SERVER_IP = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
SRC_PORT = 12345
DST_PORT = 443
TOKEN_FILE = "group_j_ddos_simulation/generated_token_j.json"
IPV6_STORE_FILE = "client_ipv6.json"
INTERFACE = "en0"
NUM_PACKETS = 50
INTERVAL_BETWEEN_PACKETS = 0.01

with open(TOKEN_FILE, "r") as f:
    token = json.load(f)

with open(IPV6_STORE_FILE, "r") as f:
    client_ip = json.load(f)["client_ip"]

print("[*] Sending legitimate traffic (Group J)...")

for i in range(NUM_PACKETS):
    shared_nonce = f"j-legit-{uuid.uuid4().hex[:8]}"
    timestamp = int(time.time())

    packet_token = base64.b64encode(
        sha256(json.dumps(token, sort_keys=True).encode()).digest()
    ).decode()

    payload = {
        "PacketToken": packet_token,
        "Nonce": shared_nonce,
        "Timestamp": timestamp,
        "Token": token
    }

    ether = Ether(src=get_if_hwaddr(INTERFACE), dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=json.dumps(payload).encode())
    sendp(pkt, iface=INTERFACE, verbose=False)

    if (i + 1) % 10 == 0:
        print(f"[+] Sent {i + 1}/{NUM_PACKETS} packets")
    time.sleep(INTERVAL_BETWEEN_PACKETS)

print("[✓] Legitimate traffic sending completed.")