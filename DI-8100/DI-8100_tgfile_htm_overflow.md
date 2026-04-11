# Stack-Based Buffer Overflow in DI-8100 tgfile_htm CGI via `fn` Parameter

## Summary
The `tgfile.htm` CGI endpoint in D-Link DI-8100 router firmware contains a stack-based buffer overflow vulnerability due to unsafe use of `sprintf` with user-supplied input. An unauthenticated (or authenticated, depending on configuration) remote attacker can send a crafted HTTP request with an overly long `fn` parameter, leading to denial of service (device reboot or web interface crash). Remote code execution cannot be ruled out.

## Affected Product
- **Vendor:** D-Link (or OEM / rebranded)
- **Product:** DI-8100 (and possibly other models sharing the same firmware base)
- **Firmware Version:** Tested on latest available version (date unknown; typical for EoL devices). The vulnerable function appears present across multiple firmware revisions.
- **Component:** `/tgfile.htm` CGI handler (`tgfile_htm` function)

## Vulnerability Details
The vulnerability resides in the `tgfile_htm` function of the HTTP daemon. The relevant disassembly snippet is:

<img width="2173" height="620" alt="image" src="https://github.com/user-attachments/assets/41c06e42-7aa4-486e-aba9-63235d56c38a" />


- The stack buffer `v11` is **128 bytes** in size.
- The format string `"notify_htm_%s"` prepends 11 characters before appending the user-controlled `fn` parameter value.
- No length validation is performed on `parm` before the `sprintf` call.
- When the `fn` parameter exceeds **117 bytes** (128 - 11), the `sprintf` writes beyond the bounds of `v11`, corrupting the stack frame.
- Overwriting the saved return address leads to control-flow hijacking upon function return. During testing, a payload of **200 bytes** reliably crashes the web server process, rendering the administrative interface unresponsive until the device is rebooted.

## Proof of Concept
The following `curl` command demonstrates the vulnerability (assuming a valid session cookie exists; the endpoint may also be accessible without authentication on some firmware builds):

```bash
curl -b cookies.txt "http://192.168.0.1/tgfile.htm?fn=$(python3 -c 'print("A"*200)')"
```

After sending this request, the device stops responding to HTTP requests (`Connection refused`), and the web server process crashes. Physical power cycling or remote reboot is required to restore normal operation.
<img width="2233" height="424" alt="image" src="https://github.com/user-attachments/assets/d7ea89cf-9ed7-4c78-8f69-830d0b0a44b1" />


## Impact
- **Confidentiality:** Low (stack memory may be leaked if partial overwrite occurs, but primary impact is DoS)
- **Integrity:** High (potential RCE)
- **Availability:** High (complete loss of web management interface and possible device reboot loop)
