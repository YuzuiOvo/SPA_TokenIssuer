import json
import base64
import time
import hmac
import uuid
from hashlib import sha256
from scapy.all import IPv6, UDP, send, Raw
import netifaces
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(BASE_DIR, "../generated_token.json")
IPV6_STORE_FILE = os.path.join(BASE_DIR, "../client_ipv6.json")
SERVER_IP = "2001:db8::1"
SRC_PORT = 12345
DST_PORT = 443

def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr["addr"].split('%')[0]
                if not ip.startswith("fe80") and ip != "::1":
                    return ip
    return "::1"

def compute_packet_token(token_dict, metadata, nonce):
    key = json.dumps(token_dict, sort_keys=True).encode()
    msg = f"{metadata['src_ip']}-{metadata['dst_ip']}-{metadata['timestamp']}-{metadata['dst_port']}{nonce}".encode()
    return hmac.new(key, msg, sha256).digest()

def forge_token_with_fake_signature(original_token):
    token_copy = original_token.copy()
    token_copy["Signature"] = base64.b64encode(b"forged_signature").decode()
    return token_copy

def send_forged_packet():
    client_ip = get_local_ipv6()

    with open(IPV6_STORE_FILE, "w") as f:
        json.dump({"client_ip": client_ip}, f)

    with open(TOKEN_FILE, "r") as f:
        real_token = json.load(f)

    forged_token = forge_token_with_fake_signature(real_token)

    nonce = str(uuid.uuid4())
    timestamp = int(time.time())

    metadata = {
        "src_ip": client_ip,
        "dst_ip": SERVER_IP,
        "timestamp": timestamp,
        "dst_port": DST_PORT
    }

    pkt_token = compute_packet_token(forged_token, metadata, nonce)

    payload = {
        "PacketToken": base64.b64encode(pkt_token).decode(),
        "Nonce": nonce,
        "Timestamp": timestamp,
        "Token": forged_token  
    }

    print(f"[*] Local IPv6 address: {client_ip}")
    print("[*] Payload Content (with forged signature):")
    print(json.dumps(payload, indent=2))

    pkt = IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=json.dumps(payload).encode())

    print("[+] Sending Group C packet ...")
    send(pkt, verbose=False)
    print("[✓] Packet sent.")

if __name__ == "__main__":
    send_forged_packet()