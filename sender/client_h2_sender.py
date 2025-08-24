import json
import base64
import time
import uuid
from hashlib import sha256
from scapy.all import IPv6, UDP, send, Raw
import netifaces
import os

SERVER_IP = "2001:db8::1" # Replace with the real IPv6 address of the listener
SRC_PORT = 12345
DST_PORT = 443
TOKEN_DIR = "client_h2"
NUM_TOKENS = 5
IPV6_STORE_FILE = "client_h2/client_ipv6.json"
INTERVAL_SECONDS = 1

def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                if not addr['addr'].startswith("fe80") and not addr['addr'].startswith("::1"):
                    return addr['addr'].split('%')[0]
    raise RuntimeError("A legal IPv6 address cannot be obtained")

def compute_packet_token(token_dict, metadata, nonce):
    key = json.dumps(token_dict, sort_keys=True).encode()
    message = f"{metadata['src_ip']}-{metadata['dst_ip']}-{metadata['timestamp']}-{metadata['dst_port']}{nonce}".encode()
    return sha256(key + message).digest()

def send_multiple_tokens():
    client_ip = get_local_ipv6()

    with open(IPV6_STORE_FILE, "w") as f:
        json.dump({"client_ip": client_ip}, f)

    for i in range(1, NUM_TOKENS + 1):
        token_path = os.path.join(TOKEN_DIR, f"generated_token_{i}.json")
        if not os.path.exists(token_path):
            print(f"[✗] Token file not found: {token_path}")
            continue

        with open(token_path, "r") as f:
            token = json.load(f)

        nonce = f"h2-token-{i}-{str(uuid.uuid4())[:8]}"
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
            "Token": token
        }

        raw = json.dumps(payload).encode()
        pkt = IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=raw)

        print(f"\n[→] Sending Token {i} with Nonce {nonce}...")
        send(pkt, verbose=False)
        time.sleep(INTERVAL_SECONDS)

    print("\n[✓] H2 five-token packets sent.")

if __name__ == "__main__":
    send_multiple_tokens()