import json, base64, time, uuid, os
from scapy.all import IPv6, UDP, Raw, send
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

PROJECT_ROOT    = "/Users/rainithfenalore/Documents/SPA_TokenIssuer"
TOKEN_FILE      = os.path.join(PROJECT_ROOT, "generated_token.json")
IPV6_STORE_FILE = os.path.join(PROJECT_ROOT, "client_ipv6.json")
PRIVATE_KEY_FILE= os.path.join(PROJECT_ROOT, "private_key.pem")   

SERVER_IP = "2001:db8::1"
SRC_PORT, DST_PORT = 12345, 443

EXPIRE_BACK_SECONDS = 24 * 3600

def ecdsa_sign_token(token_dict: dict, priv_pem: str) -> str:
    """Perform an ECDSA-SHA256 Signature on token_dict (excluding the signature field) and return base64(der)."""
    key = ECC.import_key(priv_pem)
    to_sign = token_dict.copy()
    to_sign.pop("Signature", None)
    token_bytes = json.dumps(to_sign, sort_keys=True).encode()
    h = SHA256.new(token_bytes)
    signer = DSS.new(key, 'fips-186-3')
    sig_der = signer.sign(h)
    return base64.b64encode(sig_der).decode()

def main():
    # Read the current token and the local IP record
    with open(TOKEN_FILE, "r") as f:
        token = json.load(f)
    with open(IPV6_STORE_FILE, "r") as f:
        local_ip = json.load(f)["client_ip"]

    # Necessary consistency check: Token.ClientID should be consistent with the local source IP; otherwise, it will be judged as IP Mismatch
    client_id = token.get("ClientID")
    if client_id and client_id != local_ip:
        print(f"[!] WARN: Token.ClientID={client_id} != local_ip={local_ip}. "
              "Packet sending will use Token.ClientID as the source to avoid IP Mismatch")

    src_ip = client_id or local_ip   

    # 1) Modify the Expiry of the Token to the past
    now = int(time.time())
    if "Expiry" in token:
        token["Expiry"] = now - EXPIRE_BACK_SECONDS
    else:
        print("There is no 'Expiry' field in the Token: The verifier only considers the token['Expiry'] as expired."
              "If this field does not exist, the expiration logic cannot be hit.")

    # 2) Re-sign the Token with ECDSA (keeping all other fields unchanged)
    with open(PRIVATE_KEY_FILE, "r") as f:
        priv_pem = f.read()
    token["Signature"] = ecdsa_sign_token(token, priv_pem)

    # 3) Construct the payload (PacketToken will not be verified in your verifier. Just fill in any base64)
    nonce = str(uuid.uuid4())
    timestamp = now  # The Timestamp does not affect the expiration judgment, but it can be retained as the current time
    packet_token_b64 = base64.b64encode(b"dummy").decode()

    payload = {
        "PacketToken": packet_token_b64,  # The verifier will decode in base64 but does not perform verification
        "Nonce": nonce,
        "Timestamp": timestamp,
        "Token": token
    }

    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    pkt = IPv6(src=src_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=raw)

    print(f"[*] Group D (Token Expiry): src={src_ip}, set token.Expiry={token.get('Expiry')} (< now={now})")
    send(pkt, verbose=False)
    print("[✓] Sent. Expected: 'Token expired — dropped.' (dropped_expired_token += 1)")

if __name__ == "__main__":
    main()