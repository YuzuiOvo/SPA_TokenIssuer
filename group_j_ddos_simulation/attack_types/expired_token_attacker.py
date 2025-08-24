import time
import uuid
import json
import base64
from hashlib import sha256
from scapy.all import IPv6, UDP, Raw, Ether, sendp, get_if_hwaddr

SERVER_IP = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
SRC_PORT = 9999
DST_PORT = 443
INTERFACE = "en0"
NUM_PACKETS = 20

TOKEN_FILE = "group_j_ddos_simulation/generated_token_j.json"
IP_FILE = "client_ipv6.json"

# === Read the client's IP and legitimate Token ===
with open(IP_FILE, "r") as f:
    client_ip = json.load(f)["client_ip"]

with open(TOKEN_FILE, "r") as f:
    token = json.load(f)

# === Modify to expiration time (expired)===
token["Expiry"] = int(time.time()) - 60  # Set to one minute ago

print("[*] Sending Expired Token attack packets...")

for _ in range(NUM_PACKETS):
    nonce = f"et-{uuid.uuid4().hex[:8]}"
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
        IPv6(src=client_ip, dst=SERVER_IP) / \
        UDP(sport=SRC_PORT, dport=DST_PORT) / \
        Raw(load=json.dumps(payload).encode())

    sendp(pkt, iface=INTERFACE, verbose=False)

print("[✓] Expired Token attack completed.")