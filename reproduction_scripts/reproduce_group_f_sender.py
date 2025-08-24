import subprocess

REPEAT_TIMES = 10  

print(f"[★] Group F: Starting Nonce reuse test, sending same packet {REPEAT_TIMES} times...")

try:
    for i in range(REPEAT_TIMES):
        print(f"[•] Sending packet {i+1}/{REPEAT_TIMES}")
        subprocess.run(["python3", "sender/client_group_f.py"], check=True)
    print(f"[✓] Group F Nonce reuse packets sent.")
except subprocess.CalledProcessError:
    print("[✗] Error occurred while sending Group F packets.")