##  Vulnerability Report: DI-8100 Router `file_exten.asp` Stack Buffer Overflow 


### 1. Executive Summary

A critical stack-based buffer overflow vulnerability exists in the `file_exten.asp` CGI script of the DI-8100 router firmware. The vulnerability is triggered when processing the `name` parameter with an overly long string during file extension configuration operations (`opt=add` or `opt=mod`). An authenticated attacker can exploit this flaw to execute arbitrary code on the underlying system, potentially leading to complete device compromise, denial of service, or lateral movement within the network.


### 2. Affected Product

- **Vendor**: D-Link (or OEM manufacturer for DI-8100)
- **Product**: DI-8100 Multi-WAN VPN Router
- **Firmware Version**: Confirmed on the version analyzed (exact version not specified, but likely all current releases)
- **Component**: `file_exten.asp` CGI handler (`/www/cgi-bin/file_exten_asp`)


### 3. Vulnerability Details

#### 3.1 Vulnerability Type
**Stack-based Buffer Overflow (CWE-121)** – Unbounded string copy using `sprintf` leading to stack memory corruption.

#### 3.2 Root Cause Analysis
The vulnerable function `file_exten_asp` (recovered via reverse engineering) processes user-supplied parameters for managing file extension policies. The critical flaw resides in the following code path (when `opt=add` or `opt=mod`):

<img width="1411" height="322" alt="image" src="https://github.com/user-attachments/assets/ed4f29a9-cb95-4a8e-b0ec-29ca8888ca86" />

<img width="1995" height="889" alt="image" src="https://github.com/user-attachments/assets/840f7ac1-c484-4c68-b725-2dc42619b152" />



**Key Issues:**
- The `name` parameter (`parm_12`) is directly passed to `sprintf` without length validation.
- The destination buffer (`___err__:__not_name____`) resides on the stack.
- An attacker can provide a `name` parameter exceeding the available stack space (~100KB minus other content), overwriting critical control data such as the return address (`$ra` in MIPS architecture) and saved frame pointer.

#### 3.3 Attack Vector
- **Remote**: Yes (HTTP POST request)
- **Authentication**: Required (valid administrative session)
- **Attack Path**: `POST /file_exten.asp` with crafted `opt=add` or `opt=mod` and oversized `name` parameter.

#### 3.4 Proof of Concept (PoC)
The attached PoC script demonstrates successful stack smashing, resulting in an immediate crash of the HTTP service (`Empty reply from server` / connection reset). The service fails to restart automatically, causing a persistent denial of service until the device is rebooted.

**PoC Snippet:**
```bash
TARGET="192.168.0.1"
curl -s -c /tmp/cookie -d "user=admin&password=admin" "http://$TARGET/login.cgi"
PAYLOAD=$(python3 -c "print('A'*102500)")
curl -X POST "http://$TARGET/file_exten.asp" -b /tmp/cookie -d "opt=add&name=$PAYLOAD"
```
<img width="2176" height="577" alt="image" src="https://github.com/user-attachments/assets/724ab5de-27db-4a6e-996f-fbc4316f5ab4" />



