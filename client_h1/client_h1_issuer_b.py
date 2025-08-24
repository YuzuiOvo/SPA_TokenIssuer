# client_h1_issuer_b.py
import json
import time
import uuid
import os
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64
import netifaces

def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr['addr'].split('%')[0]
                if not ip.startswith("fe80") and not ip.startswith("::1"):
                    return ip
    raise RuntimeError("No legal IPv6 address was found")

TOKEN_FILE = "client_h1/generated_token_b.json"
KEY_FILE = "client_h1/private_key_b.pem"
PUB_FILE = "client_h1/public_credential_b.json"
TOKEN_VALIDITY_SECONDS = 3600
NONCE_SHARED = "h1-multiclient-shared-nonce-001"

print("[*] Detecting local IPv6...")
client_ip = get_local_ipv6()
print(f"[✓] Local IPv6 detected: {client_ip}")

key = ECC.generate(curve="P-256")
pub_key = key.public_key()

with open(KEY_FILE, "wt") as f:
    f.write(key.export_key(format="PEM"))
print(f"[+] Private key B saved to: {KEY_FILE}")

token = {
    "ClientID": client_ip,
    "Expiry": int(time.time()) + TOKEN_VALIDITY_SECONDS,
    "Nonce": NONCE_SHARED,
    "Scope": {
        "dst_port": 443,
        "protocol": "TCP"
    }
}

token_bytes = json.dumps(token, sort_keys=True).encode()
h = SHA256.new(token_bytes)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(h)
token["Signature"] = base64.b64encode(signature).decode()

with open(TOKEN_FILE, "wt") as f:
    json.dump(token, f, indent=2)
print(f"[+] Token B saved to: {TOKEN_FILE}")

pub_cred = {
    "PublicKey": pub_key.export_key(format="PEM"),
    "TokenPolicy": {
        "validity_seconds": TOKEN_VALIDITY_SECONDS,
        "algorithm": "ECDSA-SHA256",
        "format": "JSON+Base64"
    },
    "IssuedAt": int(time.time())
}
with open(PUB_FILE, "wt") as f:
    json.dump(pub_cred, f, indent=2)
print(f"[+] Public credential B saved to: {PUB_FILE}")