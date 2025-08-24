import json
import uuid
import time
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64

VALIDITY_SECONDS = 3600
KEY_FILE = "group_i/private_key_i1.pem"
PUB_CRED_FILE = "group_i/public_credential_i1.json"
TOKEN_FILE = "group_i/generated_token_i1.json"

import netifaces
def get_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr['addr']
                if not ip.startswith("fe80") and not ip.startswith("::1"):
                    return ip.split('%')[0]
    raise RuntimeError("No valid IPv6 address found")

client_ip = get_ipv6()

key = ECC.generate(curve='P-256')
with open(KEY_FILE, "wt") as f:
    f.write(key.export_key(format='PEM'))

pubkey_pem = key.public_key().export_key(format='PEM')
pub_cred = {
    "PublicKey": pubkey_pem,
    "TokenPolicy": {
        "validity_seconds": VALIDITY_SECONDS,
        "algorithm": "ECDSA-SHA256",
        "format": "JSON+Base64"
    },
    "IssuedAt": int(time.time())
}
with open(PUB_CRED_FILE, "wt") as f:
    json.dump(pub_cred, f, indent=2)

expiry = int(time.time()) + VALIDITY_SECONDS
token = {
    "ClientID": client_ip,
    "Expiry": expiry,
    "Nonce": str(uuid.uuid4()),
    "Scope": {
        "dst_port": 443,
        "protocol": "TCP"
    }
}

token_bytes = json.dumps(token, sort_keys=True).encode()
h = SHA256.new(token_bytes)
signer = DSS.new(key, 'fips-186-3')
sig = signer.sign(h)
token["Signature"] = base64.b64encode(sig).decode()

with open(TOKEN_FILE, "wt") as f:
    json.dump(token, f, indent=2)

print("[✓] Group I1 token generation completed.")
print(f"[*] IPv6: {client_ip}")
print(f"[+] Token saved to: {TOKEN_FILE}")
print(f"[+] Public credential saved to: {PUB_CRED_FILE}")
print(f"[+] Private key saved to: {KEY_FILE}")