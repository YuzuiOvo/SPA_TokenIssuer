import json
import base64
import time
import hmac
from hashlib import sha256
from scapy.all import IPv6, UDP, send, Raw
import netifaces
import uuid

SERVER_IP = "2001:db8::1"
SRC_PORT = 12345
DST_PORT = 443
TOKEN_FILE = "group_i/generated_token_i1.json"
PRIVATE_KEY_FILE = "group_i/private_key_i1.pem"
IPV6_STORE_FILE = "client_ipv6.json"
PAYLOAD_DUMP_FILE = "last_sent_payload.json"

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

def send_token_packet(verbose=False):
    client_ip = get_local_ipv6()

    if verbose:
        print(f"[*] Local IPv6 address: {client_ip}")

    with open(TOKEN_FILE, "r") as f:
        token = json.load(f)

    token["ClientID"] = client_ip

    nonce = f"i1-delay-{uuid.uuid4().hex[:8]}"
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

    if verbose:
        print("[*] Payload Content:")
        print(json.dumps(payload, indent=2))

    pkt = IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=json.dumps(payload).encode())

    start_time = time.time()
    send(pkt, verbose=False)
    end_time = time.time()

    if verbose:
        print("[✓] Packet sent.")

    with open(PAYLOAD_DUMP_FILE, "w") as f:
        json.dump(payload, f, indent=2)

    delay_ms = round((end_time - start_time) * 1000, 3)
    if verbose:
        print(f"[✓] Local send delay = {delay_ms} ms")

    with open(IPV6_STORE_FILE, "w") as f:
        json.dump({"client_ip": client_ip}, f)

    return delay_ms

if __name__ == "__main__":
    send_token_packet(verbose=True)