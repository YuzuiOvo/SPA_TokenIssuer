import json
import base64
import time
import hmac
import uuid
import os
from hashlib import sha256
from pathlib import Path
from scapy.all import IPv6, UDP, send, Raw
import netifaces
import argparse

# ====== Path configuration (consistent with Group A) ======
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(BASE_DIR, "../generated_token.json")
IPV6_STORE_FILE = os.path.join(BASE_DIR, "../client_ipv6.json")
CAPTURE_DIR = os.path.join(BASE_DIR, "../captures")
# This script saves the payload used for replay here:
REPLAY_PAYLOAD_FILE = os.path.join(CAPTURE_DIR, "group_b_replay_payload.json")

SERVER_IP = "2001:db8::1"
SRC_PORT = 12345
DST_PORT = 443

# ====== Get local IPv6 address (same approach as Group A) ======
def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr["addr"].split('%')[0]
                if not ip.startswith("fe80") and ip != "::1":
                    return ip
    return "::1"

# ====== Compute PacketToken (identical to Group A) ======
def compute_packet_token(token_dict, metadata, nonce):
    key = json.dumps(token_dict, sort_keys=True).encode()
    msg = f"{metadata['src_ip']}-{metadata['dst_ip']}-{metadata['timestamp']}-{metadata['dst_port']}{nonce}".encode()
    return hmac.new(key, msg, sha256).digest()

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def build_valid_payload(client_ip: str, token: dict, nonce: str, timestamp: int) -> bytes:
    metadata = {
        "src_ip": client_ip,
        "dst_ip": SERVER_IP,
        "timestamp": timestamp,
        "dst_port": DST_PORT
    }
    pkt_token = compute_packet_token(token, metadata, nonce)
    payload = {
        "PacketToken": base64.b64encode(pkt_token).decode(),
        "Nonce": nonce,
        "Timestamp": timestamp,
        "Token": token
    }
    # Compact JSON to guarantee byte-for-byte identical replay
    return json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")

def send_raw_payload(src_ip: str, raw_bytes: bytes, note: str):
    pkt = IPv6(src=src_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=raw_bytes)
    print(f"[+] Sending Group B packet ({note}) ...")
    send(pkt, verbose=False)
    print("[✓] Sent.")

def main():
    parser = argparse.ArgumentParser(description="Group B - Replay/Nonce-Reuse (self-contained)")
    parser.add_argument("--replay-only", action="store_true",
                        help="Send only the replay packet using the saved payload file.")
    parser.add_argument("--payload", default=REPLAY_PAYLOAD_FILE,
                        help="Path to saved payload for replay (default: ../captures/group_b_replay_payload.json)")
    args = parser.parse_args()

    ensure_dir(CAPTURE_DIR)
    payload_path = Path(args.payload)

    if args.replay_only:
        # Replay-only mode: read saved payload and send it once
        if not payload_path.exists():
            print(f"[!] Replay payload not found: {payload_path}")
            print("    Run without --replay-only first to generate and seed a valid payload.")
            return
        raw_bytes = payload_path.read_bytes()
        # Use current local IPv6 as source (should match the binding in your token policy)
        src_ip = get_local_ipv6()
        send_raw_payload(src_ip, raw_bytes, "replay-only")
        print("[i] Expected verifier classification: Nonce Reuse / Replay.")
        return

    # Default: self-contained flow (1) send a valid packet, (2) replay the exact same bytes
    client_ip = get_local_ipv6()
    with open(IPV6_STORE_FILE, "w") as f:
        json.dump({"client_ip": client_ip}, f)

    with open(TOKEN_FILE, "r") as f:
        token = json.load(f)

    # Use the same nonce and timestamp for both packets (seed + replay)
    nonce = str(uuid.uuid4())
    timestamp = int(time.time())

    raw_bytes = build_valid_payload(client_ip, token, nonce, timestamp)

    # Save a copy for future --replay-only use or for archival in the thesis
    payload_path.write_bytes(raw_bytes)
    with open(payload_path.with_name("group_b_replay_payload_pretty.json"), "w") as f:
        json.dump(json.loads(raw_bytes.decode("utf-8")), f, indent=2)

    print(f"[*] Local IPv6 address: {client_ip}")
    print(f"[→] Replay payload saved to: {payload_path}")

    # (1) Send valid seed packet (should be ACCEPTED)
    send_raw_payload(client_ip, raw_bytes, "seed (valid)")

    # Small delay to avoid burst artifacts; adjust as needed
    time.sleep(0.05)

    # (2) Replay exactly the same bytes (should be DROPPED as Nonce Reuse/Replay)
    send_raw_payload(client_ip, raw_bytes, "replay (exact same payload)")

    print("[i] Expected verifier result: first ACCEPT, then DROP (reason=Nonce Reuse/Replay).")

if __name__ == "__main__":
    main()