import json, base64, time, uuid, os, argparse
from scapy.all import IPv6, UDP, Raw, send

# ====== Path configuration (consistent with your project) ======
PROJECT_ROOT     = "/Users/rainithfenalore/Documents/SPA_TokenIssuer"
TOKEN_FILE       = os.path.join(PROJECT_ROOT, "generated_token.json")
IPV6_STORE_FILE  = os.path.join(PROJECT_ROOT, "client_ipv6.json")  # For logging reference only

# ====== Default parameters ======
SERVER_IP_DEFAULT   = "2001:db8::1"
SRC_PORT_DEFAULT    = 12345
DST_PORT_DEFAULT    = 443
FORGED_SRC_DEFAULT  = "2001:db8::dead:beef"   # Forged source address (can be overridden with --src)

def load_token():
    with open(TOKEN_FILE, "r") as f:
        return json.load(f)

def load_bound_ip():
    try:
        with open(IPV6_STORE_FILE, "r") as f:
            return json.load(f).get("client_ip")
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser(description="Group E - IP Spoofing (expect IP Mismatch)")
    ap.add_argument("--server", default=SERVER_IP_DEFAULT, help="Verifier IPv6 address")
    ap.add_argument("--src",    default=FORGED_SRC_DEFAULT, help="Forged IPv6 source address")
    ap.add_argument("--sport",  type=int, default=SRC_PORT_DEFAULT)
    ap.add_argument("--dport",  type=int, default=DST_PORT_DEFAULT)
    args = ap.parse_args()

    token   = load_token()
    real_ip = load_bound_ip()   # For logging reference only
    forged  = args.src

    # --- Security and consistency checks (do not modify token, keep signature valid) ---
    now = int(time.time())
    expiry = token.get("Expiry")
    if expiry is None:
        print("[!] Token has no 'Expiry' field. Your verifier relies on token['Expiry'] for expiry checks.")
        print("    This is fine for Group E, but make sure tokens are fresh (not expired).")
    else:
        if now >= expiry:
            print(f"[!] Token is already expired (now={now} >= Expiry={expiry}).")
            print("    Re-run token_issuer.py to mint a fresh token before running Group E,")
            print("    otherwise the verifier will classify as 'Expired Token' instead of 'IP Mismatch'.")
            return

    client_id = token.get("ClientID")
    if client_id is None:
        print("[!] Token has no 'ClientID'. Your verifier compares Token['ClientID'] with IPv6 src.")
        print("    Without ClientID, IP mismatch cannot be evaluated. Aborting.")
        return

    if forged == client_id:
        print(f"[!] Forged src equals Token.ClientID ({client_id}). This will NOT trigger IP Mismatch.")
        print("    Use --src to set a different IPv6 address (e.g., --src 2001:db8::dead:beef).")
        return

    # --- Build payload (PacketToken not verified, any base64 value is acceptable) ---
    nonce = str(uuid.uuid4())
    timestamp = now
    packet_token_b64 = base64.b64encode(b"dummy").decode()

    payload = {
        "PacketToken": packet_token_b64,
        "Nonce": nonce,
        "Timestamp": timestamp,
        "Token": token
    }

    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    print("========== Group E: IP Spoofing (IP Mismatch) ==========")
    print(f"Token.ClientID (expected src): {client_id}")
    print(f"Actual IPv6 src (forged)     : {forged}")
    print(f"Real local IPv6 (for reference): {real_ip}")
    print(f"Server (dst)                 : {args.server}")
    print("=========================================================")

    # --- Construct and send UDP/IPv6 packet (with forged source address) ---
    pkt = IPv6(src=forged, dst=args.server) / UDP(sport=args.sport, dport=args.dport) / Raw(load=raw)
    send(pkt, verbose=False)
    print("[✓] Sent. Expected classification: IP Mismatch (dropped_ip_mismatch += 1)")

if __name__ == "__main__":
    main()