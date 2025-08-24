import json
import base64
import time
import uuid
import hmac
from hashlib import sha256
from scapy.all import IPv6, UDP, send, Raw
import netifaces
import os

SERVER_IP = "2001:db8::1"
SRC_PORT = 12345
DST_PORT = 443
PRIVATE_TOKEN_FILE = "client_h1/generated_token_b.json"  
IPV6_STORE_FILE = "client_ipv6.json"
PAYLOAD_LOG_FILE = "last_sent_payload.json"
SHARED_NONCE = "h1-multiclient-shared-nonce-001" 

def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr['addr'].split('%')[0]
                if not ip.startswith("fe80") and not ip.startswith("::1"):
                    return ip
    return "::1" 

def compute_packet_token(token_dict, metadata, nonce):
    key = json.dumps(token_dict, sort_keys=True).encode()
    message = f"{metadata['src_ip']}-{metadata['dst_ip']}-{metadata['timestamp']}-{metadata['dst_port']}{nonce}".encode()
    return hmac.new(key, message, sha256).digest()

def send_packet():
    client_ip = get_local_ipv6()

    with open(IPV6_STORE_FILE, "w") as f:
        json.dump({"client_ip": client_ip}, f)

    token = json.load(open(PRIVATE_TOKEN_FILE, "r"))

    timestamp = int(time.time())

    metadata = {
        "src_ip": client_ip,
        "dst_ip": SERVER_IP,
        "timestamp": timestamp,
        "dst_port": DST_PORT
    }

    pkt_token = compute_packet_token(token, metadata, SHARED_NONCE)

    payload = {
        "PacketToken": base64.b64encode(pkt_token).decode(),
        "Nonce": SHARED_NONCE,
        "Timestamp": timestamp,
        "Token": token
    }

    print(f"[*] Local IPv6 address: {client_ip}")
    print("[*] Payload Content (Client B with shared Nonce):")
    print(json.dumps(payload, indent=2))

    pkt = IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=json.dumps(payload).encode())

    print("[+] Sending Group H1-B packet...")
    send(pkt, verbose=False)
    print("[✓] Packet sent.")

    with open(PAYLOAD_LOG_FILE, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[✓] Payload saved to {PAYLOAD_LOG_FILE}")

if __name__ == "__main__":
    send_packet()