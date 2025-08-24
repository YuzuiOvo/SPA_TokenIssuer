import json
import uuid
import time
import os
import base64
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

DST_PORT = 443
PROTOCOL = "TCP"
VALIDITY_PERIOD = 3600  
IPV6_FILE = "client_ipv6.json"  # Automatically read IPv6 addresses

OUTPUT_DIR = "group_j_ddos_simulation"
TOKEN_FILE = os.path.join(OUTPUT_DIR, "generated_token_j.json")
PUB_CRED_FILE = os.path.join(OUTPUT_DIR, "public_credential_j.json")
PRIV_KEY_FILE = os.path.join(OUTPUT_DIR, "private_key_j.pem")

with open(IPV6_FILE, "r") as f:
    client_ipv6 = json.load(f)["client_ip"]

key = ECC.generate(curve='P-256')
with open(PRIV_KEY_FILE, "wt") as f:
    f.write(key.export_key(format='PEM'))

pubkey = key.public_key()
with open(PUB_CRED_FILE, "wt") as f:
    json.dump({
        "PublicKey": pubkey.export_key(format='PEM'),
        "TokenPolicy": {
            "validity_seconds": VALIDITY_PERIOD,
            "algorithm": "ECDSA-SHA256"
        }
    }, f, indent=2)


token = {
    "ClientID": client_ipv6,
    "Expiry": int(time.time()) + VALIDITY_PERIOD,
    "Nonce": str(uuid.uuid4()),
    "Scope": {
        "dst_port": DST_PORT,
        "protocol": PROTOCOL
    }
}

token_bytes = json.dumps(token, sort_keys=True).encode()
h = SHA256.new(token_bytes)
sig = DSS.new(key, 'fips-186-3').sign(h)
token["Signature"] = base64.b64encode(sig).decode()

with open(TOKEN_FILE, "wt") as f:
    json.dump(token, f, indent=2)

print(f"[✓] Token and credentials generated in: {OUTPUT_DIR}")