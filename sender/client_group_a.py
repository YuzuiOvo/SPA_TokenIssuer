import json
import base64
import time
import hmac
import uuid
from hashlib import sha256
from scapy.all import IPv6, UDP, send, Raw
import netifaces
import os

# ====== Configuration parameters ======
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(BASE_DIR, "../generated_token.json")
IPV6_STORE_FILE = os.path.join(BASE_DIR, "../client_ipv6.json")
SERVER_IP = "2001:db8::1"
SRC_PORT = 12345
DST_PORT = 443

# ====== Get local IPv6 address ======
def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr["addr"].split('%')[0]
                if not ip.startswith("fe80") and ip != "::1":
                    return ip
    return "::1"

# ====== Compute PacketToken ======
def compute_packet_token(token_dict, metadata, nonce):
    key = json.dumps(token_dict, sort_keys=True).encode()
    msg = f"{metadata['src_ip']}-{metadata['dst_ip']}-{metadata['timestamp']}-{metadata['dst_port']}{nonce}".encode()
    return hmac.new(key, msg, sha256).digest()

# ====== Packet sending logic ======
def send_packet():
    client_ip = get_local_ipv6()

    # Save client IPv6 address to file
    with open(IPV6_STORE_FILE, "w") as f:
        json.dump({"client_ip": client_ip}, f)

    # Load pre-issued token
    with open(TOKEN_FILE, "r") as f:
        token = json.load(f)

    nonce = str(uuid.uuid4())
    timestamp = int(time.time())

    metadata = {
        "src_ip": client_ip,
        "dst_ip": SERVER_IP,
        "timestamp": timestamp,
        "dst_port": DST_PORT
    }

    pkt_token = compute_packet_token(token, metadata, nonce)

    payload = {
        "PacketToken": base64.b64encode(pkt_token).decode(),
        "Nonce": nonce,
        "Timestamp": timestamp,
        "Token": token  # Include full Token field
    }

    print(f"[*] Local IPv6 address: {client_ip}")
    print("[*] Payload Content:")
    print(json.dumps(payload, indent=2))

    pkt = IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=json.dumps(payload).encode())
    print("[+] Sending Group A packet (valid token)...")
    send(pkt, verbose=False)
    print("[✓] Packet sent.")

if __name__ == "__main__":
    send_packet()