import json
import time
import base64
import uuid
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

# ====== Configuration parameters ======
TOKEN_VALIDITY_SECONDS = 3600  # Token validity period, unit: seconds
OUTPUT_CREDENTIAL_FILE = "public_credential.json"
OUTPUT_TOKEN_FILE = "generated_token.json"
OUTPUT_PRIVATE_KEY_FILE = "private_key.pem"  # Private key export path

# ====== Generate the key pair and export the private key file ======
def generate_key_pair():
    key = ECC.generate(curve='P-256')
    private_key = key
    public_key = key.public_key()
    
    # Write to the private key file
    with open(OUTPUT_PRIVATE_KEY_FILE, "w") as f:
        f.write(private_key.export_key(format='PEM'))
    print(f"[+] Private key written to: {OUTPUT_PRIVATE_KEY_FILE}")
    
    return private_key, public_key

# ====== Construct the token content ======
def create_token(client_id, expiry_ts, nonce, scope, private_key):
    payload = {
        "ClientID": client_id,
        "Expiry": expiry_ts,
        "Nonce": nonce,
        "Scope": scope
    }
    token_json = json.dumps(payload, sort_keys=True).encode()
    h = SHA256.new(token_json)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    payload["Signature"] = base64.b64encode(signature).decode()
    return payload

# ====== Export public key credentials (for edge use) ======
def export_public_credential(public_key, token_policy):
    pem = public_key.export_key(format='PEM')
    credential = {
        "PublicKey": pem,
        "TokenPolicy": token_policy,
        "IssuedAt": int(time.time())
    }
    with open(OUTPUT_CREDENTIAL_FILE, "w") as f:
        json.dump(credential, f, indent=2)
    print(f"[+] Public credential written to: {OUTPUT_CREDENTIAL_FILE}")

# ====== Write to Token output ======
def export_token(token):
    with open(OUTPUT_TOKEN_FILE, "w") as f:
        json.dump(token, f, indent=2)
    print(f"[+] Token written to: {OUTPUT_TOKEN_FILE}")

if __name__ == "__main__":
    print("[*] Generating ECDSA key pair...")
    sk, pk = generate_key_pair()

    client_ip = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"
    expiry_time = int(time.time()) + TOKEN_VALIDITY_SECONDS
    nonce = str(uuid.uuid4())
    scope = {"dst_port": 443, "protocol": "TCP"}

    print("[*] Creating signed token...")
    token = create_token(client_ip, expiry_time, nonce, scope, sk)

    print("[*] Exporting public credential...")
    token_policy = {
        "validity_seconds": TOKEN_VALIDITY_SECONDS,
        "algorithm": "ECDSA-SHA256",
        "format": "JSON+Base64"
    }
    export_public_credential(pk, token_policy)

    print("[*] Exporting token...")
    export_token(token)

    print("[✓] Token Issuer completed successfully.")