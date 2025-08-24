import subprocess

REPEAT = 20  # 

print("[★] Group D: Starting expired token test (Token Expiry)...")

for i in range(REPEAT):
    print(f"[→] Attempt #{i+1}")
    try:
        subprocess.run(["python3", "sender/client_group_d.py"], check=True)
    except subprocess.CalledProcessError:
        print("[✗] Error occurred while sending expired token packet.")

print("[✓] Group D test completed.")