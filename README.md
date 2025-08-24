# SPA_TokenIssuer

Selective Packet Authorization (SPA): A Token-Based Default-Off Mechanism for Securing IPv6 Networks.  

---

## 📖 Project Overview
Distributed Denial-of-Service (DDoS) attacks remain a critical threat to Internet availability.  
This project designs and evaluates a **Selective Packet Authorization (SPA)** mechanism — a *default-off* architecture where only IPv6 packets carrying valid cryptographic tokens are allowed through the edge verifier.

Core contributions:
- **Robust Security**: Replay, forgery, spoofing, expiry violations, and token omission are reliably blocked.  
- **Policy Enforcement**: Token expiry, IP binding, and nonce uniqueness consistently validated.  
- **Operational Feasibility**: Prototype implementation using Python, Scapy, and ECC (NIST P-256).  

---

## ⚙️ Requirements
- Python 3.12+
- [Scapy](https://scapy.net/)
- [PyCryptodome](https://www.pycryptodome.org/)
- Matplotlib, Netifaces

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 🌐 IPv6 Environment Notes
This project is **IPv6-only**. Please ensure:

1. Your system has a **globally routable IPv6 address** (not just `fe80::` link-local).  
   - On macOS/Linux, check with:
     ```bash
     ifconfig | grep inet6
     ```

2. In all client scripts (`client_group_*.py`), you may need to **manually update the `CLIENT_IPV6` variable** to match your own IPv6 address.  
   Example:
   ```python
   CLIENT_IPV6 = "2a00:23c8:afd9:e101:4d5:e821:5b53:e91f"  # replace with your IPv6

3.	If no valid IPv6 address is configured, packets will not be transmitted correctly.

---

## 📊 Experiment Groups
- **Group A**: Baseline legitimate packets  
- **Group B**: Replay / Nonce reuse  
- **Group C**: Forged signatures  
- **Group D**: Expired tokens  
- **Group E**: IP spoofing  
- **Group F–J**: Extended scenarios including DDoS simulation  
- **Group I1–I3**: Performance evaluation (latency, throughput)
