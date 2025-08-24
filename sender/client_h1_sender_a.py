import json
import base64
import time
import hmac
from hashlib import sha256
from scapy.all import IPv6, UDP, send, Raw
import netifaces
import os
import sys

print("[DEBUG] Script started.")

SERVER_IP = "2001:db8::1"
SRC_PORT = 12345
DST_PORT = 443
TOKEN_FILE = "client_h1/generated_token_a.json"
IPV6_STORE_FILE = "client_ipv6.json"
PAYLOAD_DUMP_FILE = "last_sent_payload.json"
SHARED_NONCE = "h1-multiclient-shared-nonce-001"

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
    return hmac.new(key, message, sha256).digest()

def send_group_h1_a_packet():
    try:
        client_ip = get_local_ipv6()
        print(f"[*] Local IPv6 address: {client_ip}")
    except Exception as e:
        print(f"[ERROR] Failed to obtain the IPv6 address of this machine: {e}")
        sys.exit(1)

    try:
        with open(IPV6_STORE_FILE, "w") as f:
            json.dump({"client_ip": client_ip}, f)
        print(f"[✓] client_ip write to {IPV6_STORE_FILE}")
    except Exception as e:
        print(f"[ERROR] write to {IPV6_STORE_FILE} failed: {e}")
        sys.exit(1)

    try:
        with open(TOKEN_FILE, "r") as f:
            token = json.load(f)
        print(f"[✓] Token loaded from {TOKEN_FILE}")
    except Exception as e:
        print(f"[ERROR] Read Token failed: {e}")
        sys.exit(1)

    token["ClientID"] = client_ip
    nonce = SHARED_NONCE
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

    print("[*] Payload Content (Client A with shared Nonce):")
    print(json.dumps(payload, indent=2))

    pkt = IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=json.dumps(payload).encode())

    print("[+] Sending Group H1-A packet...")
    send(pkt, verbose=False)
    print("[✓] Packet sent.")

    try:
        with open(PAYLOAD_DUMP_FILE, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"[✓] Payload saved to {PAYLOAD_DUMP_FILE}")
    except Exception as e:
        print(f"[ERROR] 写入 Payload 文件失败: {e}")

if __name__ == "__main__":
    send_group_h1_a_packet()