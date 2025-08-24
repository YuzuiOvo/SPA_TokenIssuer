import json
import base64
import time
import signal
from hashlib import sha256
from scapy.all import sniff, IPv6, UDP, Raw
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import statistics

# ====== Configuration parameters ======
PORT_LISTEN = 443
CREDENTIAL_FILE = "public_credential.json"
IPV6_CLIENT_FILE = "client_ipv6.json"
NONCE_WINDOW_SECONDS = 300
LOG_FILE = "i1_verification_log.json"

# ====== Statistics counter ======
stats = {
    "total_received": 0,
    "accepted": 0,
    "dropped_signature_invalid": 0,
    "dropped_expired_token": 0,
    "dropped_nonce_reuse": 0,
    "dropped_ip_mismatch": 0,
    "dropped_missing_token": 0,
    "dropped_other": 0
}
recent_nonces = {}
verification_delays = []

# ====== Load public key ======
with open(CREDENTIAL_FILE, "r") as f:
    data = json.load(f)
    pubkey_pem = data["PublicKey"]
    pubkey = ECC.import_key(pubkey_pem)

# ====== Load target client IPv6 address (source) ======
with open(IPV6_CLIENT_FILE, "r") as f:
    CLIENT_IP = json.load(f)["client_ip"]

# ====== Catch Ctrl+C and save verification log ======
def write_log_and_exit(signalnum, frame):
    result = {
        "stats": stats,
        "delay_samples": verification_delays,
        "delay_summary_ms": {}
    }
    if verification_delays:
        result["delay_summary_ms"] = {
            "avg": round(statistics.mean(verification_delays), 3),
            "max": round(max(verification_delays), 3),
            "min": round(min(verification_delays), 3),
            "stddev": round(statistics.stdev(verification_delays), 3) if len(verification_delays) > 1 else 0.0
        }

    with open(LOG_FILE, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\n[✓] Delay log saved to: {LOG_FILE}")
    print(f"[✓] Final stats: {json.dumps(result['delay_summary_ms'], indent=2)}")
    exit(0)

signal.signal(signal.SIGINT, write_log_and_exit)

# ====== Verification logic ======
def verify_packet(pkt):
    if not pkt.haslayer(IPv6) or not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
        return

    stats["total_received"] += 1
    recv_time = time.time()

    try:
        payload = json.loads(pkt[Raw].load.decode())
    except:
        stats["dropped_missing_token"] += 1
        print("[!] Failed to decode JSON — dropped.")
        return

    if not {"PacketToken", "Nonce", "Timestamp", "Token"}.issubset(payload):
        stats["dropped_missing_token"] += 1
        print("[!] Missing required fields — dropped.")
        return

    packet_token = base64.b64decode(payload["PacketToken"])
    nonce = payload["Nonce"]
    timestamp = payload["Timestamp"]
    token = payload["Token"]

    # ===== Token field integrity check =====
    required_token_fields = {"ClientID", "Expiry", "Nonce", "Scope", "Signature"}
    if not isinstance(token, dict) or not required_token_fields.issubset(token):
        stats["dropped_missing_token"] += 1
        print("[!] Token structure invalid or missing fields — dropped.")
        return

    # ===== Signature verification =====
    try:
        sig = base64.b64decode(token["Signature"])
        token_copy = token.copy()
        del token_copy["Signature"]
        token_bytes = json.dumps(token_copy, sort_keys=True).encode()
        h = SHA256.new(token_bytes)
        verifier = DSS.new(pubkey, 'fips-186-3')
        verifier.verify(h, sig)
    except:
        stats["dropped_signature_invalid"] += 1
        print("[✗] Signature invalid — dropped.")
        return

    # ===== Expiry check =====
    if time.time() > token["Expiry"]:
        stats["dropped_expired_token"] += 1
        print("[✗] Token expired — dropped.")
        return

    # ===== IP check =====
    if token["ClientID"] != pkt[IPv6].src:
        stats["dropped_ip_mismatch"] += 1
        print("[✗] Source IP mismatch — dropped.")
        return

    # ===== Nonce check =====
    if nonce in recent_nonces and (recv_time - recent_nonces[nonce]) < NONCE_WINDOW_SECONDS:
        stats["dropped_nonce_reuse"] += 1
        print("[✗] Nonce reuse detected — dropped.")
        return

    # ===== Successful verification + delay measurement =====
    delay_ms = (recv_time - timestamp) * 1000
    verification_delays.append(round(delay_ms, 3))
    recent_nonces[nonce] = recv_time
    stats["accepted"] += 1
    print(f"[✓] Packet passed verification — forwarded. Delay = {delay_ms:.2f} ms")

# ====== Start listener ======
print(f"[*] Listening on UDP port {PORT_LISTEN} for IPv6 packets from client IP: {CLIENT_IP}")
sniff(filter=f"ip6 and udp port {PORT_LISTEN}", prn=verify_packet)