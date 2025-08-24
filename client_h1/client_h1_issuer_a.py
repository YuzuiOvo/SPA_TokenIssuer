import os
import json
import time
import uuid
import base64
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

OUTPUT_DIR = "client_h1"
OUTPUT_TOKEN_FILE = os.path.join(OUTPUT_DIR, "generated_token_a.json")
OUTPUT_CREDENTIAL_FILE = os.path.join(OUTPUT_DIR, "public_credential_a.json")
PRIVATE_KEY_FILE = os.path.join(OUTPUT_DIR, "private_key_a.pem")

TOKEN_VALIDITY_SECONDS = 3600

def generate_key_pair():
    key = ECC.generate(curve='P-256')
    return key, key.public_key()

def create_token(client_ip, expiry_ts, nonce, scope, private_key):
    payload = {
        "ClientID": client_ip,
        "Expiry": expiry_ts,
        "Nonce": nonce,
        "Scope": scope
    }
    h = SHA256.new(json.dumps(payload, sort_keys=True).encode())
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    payload["Signature"] = base64.b64encode(signature).decode()
    return payload

def export_public_credential(public_key):
    pem = public_key.export_key(format='PEM')
    credential = {
        "PublicKey": pem,
        "TokenPolicy": {
            "validity_seconds": TOKEN_VALIDITY_SECONDS,
            "algorithm": "ECDSA-SHA256",
            "format": "JSON+Base64"
        },
        "IssuedAt": int(time.time())
    }
    with open(OUTPUT_CREDENTIAL_FILE, "w") as f:
        json.dump(credential, f, indent=2)
    print(f"[+] Public credential written to: {OUTPUT_CREDENTIAL_FILE}")

def export_token_and_key(token, private_key):
    with open(OUTPUT_TOKEN_FILE, "w") as f:
        json.dump(token, f, indent=2)
    print(f"[+] Token written to: {OUTPUT_TOKEN_FILE}")

    with open(PRIVATE_KEY_FILE, "wt") as f:
        f.write(private_key.export_key(format='PEM'))
    print(f"[+] Private key written to: {PRIVATE_KEY_FILE}")

if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("[*] Generating ECDSA key pair...")
    sk, pk = generate_key_pair()

    client_ip = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
    expiry_time = int(time.time()) + TOKEN_VALIDITY_SECONDS
    nonce = str(uuid.uuid4())
    scope = {"dst_port": 443, "protocol": "TCP"}

    print("[*] Creating signed token...")
    token = create_token(client_ip, expiry_time, nonce, scope, sk)

    export_public_credential(pk)
    export_token_and_key(token, sk)

    print("[✓] Issuer for Group H1-A completed successfully.")