# Netcore NR268 Vulnerability Reports

Public vulnerability reports for Netcore NR268 firmware `NR268-V1.7.121109.bin`.
Each advisory follows a standard disclosure format: Summary, Technical Details, Affected Endpoint, Proof of Concept, Outcome, and Impact.

Lab requests in the proofs of concept use `http://192.168.1.1` and HTTP Basic authentication `admin:admin`. Replace those values with the target device address and valid management credentials.

Contributors: Zhou Ao, Zhang Yu, Yang Yang, Liu Xin @Nebusec  
Contact: vuln@nebusec.ai

## Advisories

- [Forgeable Firmware Authenticity Check in mtd_write](2026.08.19-netcore-nr268-firmware-forgery.md)
- [Parameter Restore Archive Bypass via Prefix Check in parame_put_file.cgi](2026.08.19-netcore-nr268-restore-bypass.md)
- [Cleartext Disclosure of Stored Service Secrets in Management Responses](2026.09.14-netcore-nr268-stored-secret-disclosure.md)
- [Cross-Site Request Forgery on Privileged Management CGI Actions](2026.09.14-netcore-nr268-privileged-cgi-csrf.md)
- [Missing Authentication on the Switch Daemon IPC Control Plane](2026.09.14-netcore-nr268-unauthenticated-switch-ipc.md)
- [Cross-Site Request Forgery on Core Network Configuration Endpoints](2026.09.14-netcore-nr268-core-network-csrf.md)
- [DDNS Management Argument Injection](2026.09.14-netcore-nr268-ddns-argument-injection.md)
- [DDNS Secret Disclosure](2026.09.14-netcore-nr268-ddns-secret-disclosure.md)
- [Stored Cross-Site Scripting in DHCP/DNS Management Pages](2026.09.14-netcore-nr268-dhcp-dns-stored-xss.md)
- [Boa Authentication Fails Open When the Auth Cache Is Missing](2026.09.14-netcore-nr268-boa-auth-fail-open.md)
- [Stored Cross-Site Scripting in L7 Call-Board List Views](2026.09.14-netcore-nr268-call-board-stored-xss.md)
- [Stored Cross-Site Scripting in L7 Policy Pages](2026.09.14-netcore-nr268-l7-policy-stored-xss.md)
- [Stack-Based Buffer Overflow in ntools_info_show.cgi](2026.09.14-netcore-nr268-ntools-stack-buffer-overflow.md)
- [Reflected Cross-Site Scripting in ntools_info_show.cgi](2026.09.14-netcore-nr268-ntools-reflected-xss.md)
- [Stack Buffer Over-read in the ARP Filter Upload Import Handler](2026.09.14-netcore-nr268-arp-import-overread.md)
- [Stored Cross-Site Scripting via DHCP Hostname Fields](2026.09.14-netcore-nr268-dhcp-hostname-stored-xss.md)
- [NULL Pointer Dereference via Missing Request Parameters](2026.09.14-netcore-nr268-missing-param-null-deref.md)
- [Cleartext Disclosure of Stored VPN and PPPoE Secrets](2026.09.14-netcore-nr268-vpn-pppoe-secret-disclosure.md)
- [Cross-Site Request Forgery on VPN and Remote-Access Write Endpoints](2026.09.14-netcore-nr268-vpn-remote-csrf.md)
