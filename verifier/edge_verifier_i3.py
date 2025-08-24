import json
import base64
import time
from scapy.all import sniff, IPv6, UDP, Raw
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# ====== Configuration parameters ======
PORT_LISTEN = 443
CREDENTIAL_FILE = "public_credential.json"  # Public key used by this verifier
IPV6_CLIENT_FILE = "client_ipv6.json"
LOG_FILE = "verification_log.json"
LISTEN_DURATION = 10  # Listening duration in seconds, adjustable

# ====== Load verification public key and client IPv6 ======
with open(CREDENTIAL_FILE, "r") as f:
    pubkey = ECC.import_key(json.load(f)["PublicKey"])

with open(IPV6_CLIENT_FILE, "r") as f:
    CLIENT_IP = json.load(f)["client_ip"]

# ====== Initialize statistics ======
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

# ====== Verification logic ======
def verify(pkt):
    if not pkt.haslayer(IPv6) or not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
        return

    stats["total_received"] += 1

    try:
        raw_bytes = pkt[Raw].load
        decoded = raw_bytes.decode()
        payload = json.loads(decoded)
    except Exception as e:
        print(f"[✗] JSON decode failed: {e}")
        stats["dropped_missing_token"] += 1
        return

    required_fields = {"PacketToken", "Nonce", "Timestamp", "Token"}
    if not required_fields.issubset(payload):
        stats["dropped_missing_token"] += 1
        return

    token = payload["Token"]
    required_token_fields = {"ClientID", "Expiry", "Nonce", "Scope", "Signature"}
    if not isinstance(token, dict) or not required_token_fields.issubset(token):
        stats["dropped_missing_token"] += 1
        return

    # Signature verification
    try:
        sig = base64.b64decode(token["Signature"])
        token_copy = token.copy()
        del token_copy["Signature"]
        token_bytes = json.dumps(token_copy, sort_keys=True).encode()
        h = SHA256.new(token_bytes)
        DSS.new(pubkey, 'fips-186-3').verify(h, sig)
    except Exception as e:
        stats["dropped_signature_invalid"] += 1
        return

    if time.time() > token["Expiry"]:
        stats["dropped_expired_token"] += 1
        return

    if token["ClientID"] != pkt[IPv6].src:
        stats["dropped_ip_mismatch"] += 1
        return

    stats["accepted"] += 1
    print("[✓] Packet accepted.")

# ====== Start listener (auto exit after timeout) ======
print(f"[*] Listening on UDP port {PORT_LISTEN} for IPv6 packets from client IP: {CLIENT_IP}")
sniff(filter=f"ip6 and udp port {PORT_LISTEN}", prn=verify, timeout=LISTEN_DURATION)

# ====== Save results ======
with open(LOG_FILE, "w") as f:
    json.dump(stats, f, indent=2)

print(f"[✓] Log saved to: {LOG_FILE}")
print(f"[✓] Final stats: {stats}")