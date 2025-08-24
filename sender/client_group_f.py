import json, base64, time, hmac, uuid, os
from hashlib import sha256
from scapy.all import IPv6, UDP, Raw, send
import netifaces

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(BASE_DIR, "../generated_token.json")
IPV6_STORE_FILE = os.path.join(BASE_DIR, "../client_ipv6.json")
SERVER_IP = "2001:db8::1"
SRC_PORT, DST_PORT = 12345, 443

def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr["addr"].split('%')[0]
                if not ip.startswith("fe80") and ip != "::1":
                    return ip
    return "::1"

def compute_packet_token(token_dict, src_ip, dst_ip, ts, dport, nonce):
    key = json.dumps(token_dict, sort_keys=True).encode()
    msg = f"{src_ip}-{dst_ip}-{ts}-{dport}{nonce}".encode()
    return base64.b64encode(hmac.new(key, msg, sha256).digest()).decode()

def build_payload(token, src_ip, ts, nonce, note):
    pkt_token = compute_packet_token(token, src_ip, SERVER_IP, ts, DST_PORT, nonce)
    payload = {
        "PacketToken": pkt_token,
        "Nonce": nonce,
        "Timestamp": ts,
        "Token": token,
        "Note": note  
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=False).encode()

def send_once(src_ip, raw_bytes, tag):
    pkt = IPv6(src=src_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=raw_bytes)
    print(f"[+] Send ({tag})")
    send(pkt, verbose=False)

def main():
    src_ip = get_local_ipv6()
    with open(IPV6_STORE_FILE, "w") as f:
        json.dump({"client_ip": src_ip}, f)
    with open(TOKEN_FILE, "r") as f:
        token = json.load(f)

    # Same Nonce
    nonce = str(uuid.uuid4())

    # Package 1: Nonce=N, ts=t1, Note=P1 → Expected ACCEPT
    ts1 = int(time.time())
    raw1 = build_payload(token, src_ip, ts1, nonce, note="P1")
    send_once(src_ip, raw1, "valid-1 (nonce=N, ts=t1, P1)")

    time.sleep(0.1)

    # Package 2: Nonce=N (same), but ts=t2 or Note=P2 (change) → Expected Nonce Reuse
    ts2 = ts1 + 1
    raw2 = build_payload(token, src_ip, ts2, nonce, note="P2")
    send_once(src_ip, raw2, "variant-2 (nonce=N, ts=t2, P2)")

    print("[i] Expected: first ACCEPT, then DROP(reason=Nonce Reuse).")

if __name__ == "__main__":
    main()