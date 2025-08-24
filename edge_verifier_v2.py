import json
import base64
import time
import signal
from hashlib import sha256
from scapy.all import sniff, IPv6, UDP, Raw
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# ====== Configuration parameters ======
PORT_LISTEN = 443
CREDENTIAL_FILE = "public_credential.json"
IPV6_CLIENT_FILE = "client_ipv6.json"
NONCE_WINDOW_SECONDS = 300
LOG_FILE = "verification_log.json"

# ====== Statistics counter ======
stats = {
    "total_received": 0,
    "accepted": 0,
    "dropped_signature_invalid": 0,
    "dropped_expired_token": 0,
    "dropped_nonce_reuse": 0,
    "dropped_ip_mismatch": 0,
    "dropped_missing_token": 0,
    "dropped_malformed_json": 0,
    "dropped_other": 0
}

recent_nonces = {}

# ====== Load public key ======
with open(CREDENTIAL_FILE, "r") as f:
    data = json.load(f)
    pubkey_pem = data["PublicKey"]
    pubkey = ECC.import_key(pubkey_pem)

# ====== Load target client IPv6 address ======
with open(IPV6_CLIENT_FILE, "r") as f:
    CLIENT_IP = json.load(f)["client_ip"]

# ====== Catch Ctrl+C and save verification log ======
def write_log_and_exit(signalnum, frame):
    with open(LOG_FILE, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"\n[✓] Log saved to: {LOG_FILE}")
    print(f"[✓] Final stats: {stats}")
    exit(0)

signal.signal(signal.SIGINT, write_log_and_exit)

# ====== Verification logic ======
def verify_packet(pkt):
    if not pkt.haslayer(IPv6) or not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
        return

    stats["total_received"] += 1

    try:
        payload = json.loads(pkt[Raw].load.decode())
    except Exception:
        stats["dropped_malformed_json"] += 1
        print("[✗] Failed to decode JSON — dropped (malformed payload).")
        return

    required_fields = {"PacketToken", "Nonce", "Timestamp", "Token"}
    if not required_fields.issubset(payload):
        stats["dropped_missing_token"] += 1
        print("[✗] Missing required fields — dropped.")
        return

    try:
        packet_token = base64.b64decode(payload["PacketToken"])
        nonce = payload["Nonce"]
        timestamp = payload["Timestamp"]
        token = payload["Token"]

        required_token_fields = {"ClientID", "Expiry", "Nonce", "Scope", "Signature"}
        if not isinstance(token, dict) or not required_token_fields.issubset(token):
            stats["dropped_missing_token"] += 1
            print("[✗] Token structure invalid or missing fields — dropped.")
            return

        sig = base64.b64decode(token["Signature"])
        token_copy = token.copy()
        del token_copy["Signature"]
        token_bytes = json.dumps(token_copy, sort_keys=True).encode()
        h = SHA256.new(token_bytes)
        verifier = DSS.new(pubkey, 'fips-186-3')
        verifier.verify(h, sig)
    except Exception:
        stats["dropped_signature_invalid"] += 1
        print("[✗] Signature invalid — dropped.")
        return

    if time.time() > token["Expiry"]:
        stats["dropped_expired_token"] += 1
        print("[✗] Token expired — dropped.")
        return

    if token["ClientID"] != pkt[IPv6].src:
        stats["dropped_ip_mismatch"] += 1
        print("[✗] Source IP mismatch — dropped.")
        return

    if nonce in recent_nonces and (time.time() - recent_nonces[nonce]) < NONCE_WINDOW_SECONDS:
        stats["dropped_nonce_reuse"] += 1
        print("[✗] Nonce reuse detected — dropped.")
        return

    recent_nonces[nonce] = time.time()
    stats["accepted"] += 1
    print("[✓] Packet passed verification — forwarded.")

# ====== Start packet listener ======
print(f"[*] Listening on UDP port {PORT_LISTEN} for IPv6 packets from client IP: {CLIENT_IP}")
sniff(filter=f"ip6 and udp port {PORT_LISTEN}", prn=verify_packet)