import os
import json
import uuid
import time
import base64
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import netifaces

OUTPUT_DIR = "client_h2"
NUM_TOKENS = 5
KEY_FILE = os.path.join(OUTPUT_DIR, "private_key_h2.pem")
CREDENTIAL_FILE = os.path.join(OUTPUT_DIR, "public_credential_h2.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr['addr'].split('%')[0]
                if not ip.startswith("fe80") and ip != "::1":
                    return ip
    return "::1"

client_ip = get_local_ipv6()
print(f"[✓] Detected client IPv6: {client_ip}")

key = ECC.generate(curve='P-256')
with open(KEY_FILE, 'wt') as f:
    f.write(key.export_key(format='PEM'))
print(f"[+] Private key saved to: {KEY_FILE}")

pubkey = key.public_key().export_key(format='PEM')
with open(CREDENTIAL_FILE, 'wt') as f:
    json.dump({"PublicKey": pubkey}, f, indent=2)
print(f"[+] Public credential saved to: {CREDENTIAL_FILE}")

# ====== Generate multiple tokens ======
now = int(time.time())

for i in range(1, NUM_TOKENS + 1):
    token = {
        "ClientID": client_ip,
        "Expiry": now + 600,
        "Nonce": str(uuid.uuid4()),
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

    token_path = os.path.join(OUTPUT_DIR, f"generated_token_{i}.json")
    with open(token_path, "wt") as f:
        json.dump(token, f, indent=2)

    print(f"[+] Token {i} saved to: {token_path}")

print("[✓] H2 five tokens generated successfully.")