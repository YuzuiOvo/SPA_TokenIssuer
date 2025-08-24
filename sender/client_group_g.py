import json
import time
from scapy.all import IPv6, UDP, send, Raw
import netifaces
import os

SERVER_IP = "2001:db8::1"
SRC_PORT = 12345
DST_PORT = 443
IPV6_STORE_FILE = "/Users/rainithfenalore/Documents/SPA_TokenIssuer/client_ipv6.json"
NUM_PACKETS = 1  

def get_local_ipv6():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr["addr"].split('%')[0]
                if not ip.startswith("fe80") and ip != "::1":
                    return ip
    return "::1"

def send_packets_missing_token():
    client_ip = get_local_ipv6()

    with open(IPV6_STORE_FILE, "w") as f:
        json.dump({"client_ip": client_ip}, f)

    timestamp = int(time.time())
    nonce = "00000000-0000-0000-0000-000000000000"

    for i in range(NUM_PACKETS):
        payload = {
            "PacketToken": "FakeTokenBase64==",  
            "Nonce": nonce,
            "Timestamp": timestamp
        }

        raw = json.dumps(payload).encode()
        pkt = IPv6(src=client_ip, dst=SERVER_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=raw)

        print(f"[>] Sending packet {i+1}/{NUM_PACKETS} (missing Token)...")
        send(pkt, verbose=False)
        time.sleep(0.2)

    print("[✓] Group G traffic sent (Token field missing).")

if __name__ == "__main__":
    send_packets_missing_token()