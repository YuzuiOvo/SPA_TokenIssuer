import json
import base64
import time
import hmac
import uuid
import socket
from hashlib import sha256
from scapy.all import IPv6, UDP, send, Raw

# ====== Configuration parameters ======
TOKEN_FILE = "generated_token.json"
SERVER_IPV6 = "2001:db8::1"        # Replace with simulated server address
CLIENT_IPV6 = "2001:db8::abcd"     # Local IPv6 address (must match Token)
DST_PORT = 443
SRC_PORT = 12345

# ====== Load Token from file ======
def load_token():
    with open(TOKEN_FILE, "r") as f:
        token = json.load(f)
    return token

# ====== Compute PacketToken (using HMAC) ======
def compute_packet_token(token_key_str, metadata_dict, nonce_str):
    # Construct packet metadata string
    data = f"{metadata_dict['src_ip']}-{metadata_dict['dst_ip']}-{metadata_dict['timestamp']}-{metadata_dict['dst_port']}"
    key_bytes = token_key_str.encode()
    message = (data + nonce_str).encode()
    signature = hmac.new(key_bytes, message, sha256).digest()
    return signature

# ====== Construct and send IPv6 packet ======
def send_packet(token):
    print("[*] Preparing IPv6 packet with embedded PacketToken...")

    nonce = token["Nonce"]
    timestamp = int(time.time())
    metadata = {
        "src_ip": CLIENT_IPV6,
        "dst_ip": SERVER_IPV6,
        "timestamp": timestamp,
        "dst_port": DST_PORT
    }

    # For HMAC example, use the raw Token content (not encrypted) as key
    token_key = json.dumps(token, sort_keys=True)  # Simplified: use Token content as HMAC key
    packet_token = compute_packet_token(token_key, metadata, nonce)

    # Construct payload (can be extended to custom header format)
    payload = {
        "PacketToken": base64.b64encode(packet_token).decode(),
        "Nonce": nonce,
        "Timestamp": timestamp
    }
    raw_data = json.dumps(payload).encode()

    # Build IPv6 UDP packet
    pkt = IPv6(src=CLIENT_IPV6, dst=SERVER_IPV6) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=raw_data)

    print(f"[*] Sending packet from {CLIENT_IPV6} to {SERVER_IPV6}:{DST_PORT} ...")
    send(pkt, verbose=False)
    print("[✓] Packet sent.")

# ====== Main entry point ======
if __name__ == "__main__":
    token = load_token()
    send_packet(token)