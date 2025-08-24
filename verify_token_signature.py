import json
import base64
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

TOKEN_FILE = "client_h1/generated_token_b.json"     
PUBKEY_FILE = "public_credential.json"              
PUBKEY_A_FILE = "client_h1/public_credential_a.json"
PUBKEY_B_FILE = "client_h1/public_credential_b.json"

def load_token(path):
    with open(path, "r") as f:
        return json.load(f)

def load_pubkey(path):
    with open(path, "r") as f:
        data = json.load(f)
        return data["PublicKey"], data

def match_key_identity(current_pem, known_pem_a, known_pem_b):
    hash_current = hashlib.sha256(current_pem.encode()).hexdigest()
    hash_a = hashlib.sha256(known_pem_a.encode()).hexdigest()
    hash_b = hashlib.sha256(known_pem_b.encode()).hexdigest()

    if hash_current == hash_a:
        return "A"
    elif hash_current == hash_b:
        return "B"
    else:
        return "Unknown"

token = load_token(TOKEN_FILE)
signature = base64.b64decode(token["Signature"])
token_copy = token.copy()
del token_copy["Signature"]

token_bytes = json.dumps(token_copy, sort_keys=True).encode()
h = SHA256.new(token_bytes)

current_pem, current_data = load_pubkey(PUBKEY_FILE)
pubkey = ECC.import_key(current_pem)

pubkey_a_pem, _ = load_pubkey(PUBKEY_A_FILE)
pubkey_b_pem, _ = load_pubkey(PUBKEY_B_FILE)
who = match_key_identity(current_pem, pubkey_a_pem, pubkey_b_pem)

print(f"[*] Loaded verifier public key identity: {who}")
print(f"[*] Verifying token signature against public key ({who})...")

try:
    verifier = DSS.new(pubkey, 'fips-186-3')
    verifier.verify(h, signature)
    print(f"[✓] Token is VALID under public key {who}.")
except:
    print(f"[✗] Token signature does NOT match public key {who}.")