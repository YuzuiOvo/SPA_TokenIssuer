import json
import time
from uuid import uuid4
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64

KEY_PATH = "client_i3/private_key_i3.pem"
PUB_CRED_PATH = "client_i3/public_credential_i3.json"
TOKEN_PATH = "client_i3/generated_token_i3.json"

key = ECC.generate(curve='P-256')
with open(KEY_PATH, "wt") as f:
    f.write(key.export_key(format='PEM'))

pub_key = key.public_key()
pub_pem = pub_key.export_key(format='PEM')

# ====== Construct a Public Credential ======
issued_at = int(time.time())
pub_credential = {
    "PublicKey": pub_pem,
    "TokenPolicy": {
        "validity_seconds": 3600,
        "algorithm": "ECDSA-SHA256",
        "format": "JSON+Base64"
    },
    "IssuedAt": issued_at
}
with open(PUB_CRED_PATH, "wt") as f:
    json.dump(pub_credential, f, indent=2)

# ====== Construct the Token (signature)=====
client_ip = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
token_obj = {
    "ClientID": client_ip,
    "Expiry": issued_at + 3600,
    "Nonce": str(uuid4()),
    "Scope": {
        "dst_port": 443,
        "protocol": "TCP"
    }
}

msg = json.dumps(token_obj, sort_keys=True).encode()
h = SHA256.new(msg)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(h)
token_obj["Signature"] = base64.b64encode(signature).decode()

# Write to the token file
with open(TOKEN_PATH, "wt") as f:
    json.dump(token_obj, f, indent=2)

print("[✓] Token, key, and public credential generated successfully for Group I3.")