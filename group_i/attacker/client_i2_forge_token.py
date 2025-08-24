import json
import time
import uuid
import base64
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import os

KEY_FILE = "group_i/attacker/fake_key.pem"
TOKEN_FILE = "group_i/attacker/forged_token.json"
CLIENT_ID = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
NONCE = "i2-forged-nonce-001"
EXPIRY_SECONDS = 3600

# ====== Generate a forged private key ======
print("[*] Generating fake ECC private key...")
key = ECC.generate(curve="P-256")
with open(KEY_FILE, "wt") as f:
    f.write(key.export_key(format="PEM"))
print(f"[✓] Fake private key saved to: {KEY_FILE}")

# ====== Construct forged Token content ======
token = {
    "ClientID": CLIENT_ID,
    "Expiry": int(time.time()) + EXPIRY_SECONDS,
    "Nonce": NONCE,
    "Scope": {
        "dst_port": 443,
        "protocol": "TCP"
    }
}

# ====== Signing with a forged private key ======
print("[*] Signing forged token with fake private key...")
token_bytes = json.dumps(token, sort_keys=True).encode()
h = SHA256.new(token_bytes)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(h)
token["Signature"] = base64.b64encode(signature).decode()

with open(TOKEN_FILE, "wt") as f:
    json.dump(token, f, indent=2)
print(f"[✓] Forged Token saved to: {TOKEN_FILE}")