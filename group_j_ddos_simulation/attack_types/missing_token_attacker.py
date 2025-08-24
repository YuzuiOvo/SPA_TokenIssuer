import time
import uuid
from scapy.all import IPv6, UDP, Raw, Ether, sendp, get_if_hwaddr

SERVER_IP = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
SRC_PORT = 9999
DST_PORT = 443
INTERFACE = "en0"
NUM_PACKETS = 20

print("[*] Sending Missing Token attack packets...")

for _ in range(NUM_PACKETS):
    payload = {
        "PacketToken": "invalid",
        "Nonce": f"mt-{uuid.uuid4().hex[:8]}",
        "Timestamp": int(time.time())
        # Token deliberately missing
    }

    pkt = Ether(src=get_if_hwaddr(INTERFACE), dst="ff:ff:ff:ff:ff:ff") / \
        IPv6(dst=SERVER_IP) / \
        UDP(sport=SRC_PORT, dport=DST_PORT) / \
        Raw(load=str(payload).encode())

    sendp(pkt, iface=INTERFACE, verbose=False)

print("[✓] Missing Token attack completed.")