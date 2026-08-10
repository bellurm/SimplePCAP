# SimplePCAP

A command-line PCAP triage and network analysis utility built with Bash and TShark.

SimplePCAP extracts useful network artifacts from packet captures and organizes them into separate reports, making it easier to identify interesting traffic without manually inspecting every packet in Wireshark.

The project is designed for security labs, CTF environments, network troubleshooting, packet analysis, and authorized forensic investigation.

---

## Features

### HTTP Analysis

SimplePCAP extracts:

- HTTP GET and POST requests
- Source and destination addresses
- Requested hosts and URIs
- POST request bodies
- HTTP Authorization headers
- HTTP Basic authentication credentials
- Visited URLs

### HTTP Cookies & Sessions

Identifies:

- `Cookie` headers
- `Set-Cookie` headers
- Session-related artifacts
- Authentication-related HTTP traffic

### FTP Analysis

Extracts:

- FTP `USER` commands
- FTP `PASS` commands
- FTP authentication traffic
- Successful login attempts based on FTP response code `230`

Successful FTP credentials are also added to a consolidated authentication report.

### NTLM / NetNTLMv2 Analysis

Extracts NTLM authentication information including:

- Username
- Domain
- Host
- Source and destination addresses

When enough information is available, SimplePCAP also reconstructs NetNTLMv2 challenge/response material into a standard hash representation for further analysis in authorized environments.

### Kerberos Analysis

Inspects Kerberos traffic and extracts:

- Message type
- Realm
- Username
- Encryption type
- Source and destination addresses

The script also attempts to identify compatible AS-REP authentication material when the required fields are available in the capture.

### DNS Analysis

Extracts DNS queries together with:

- Frame number
- Source address
- Queried domain name

### WinRM / PSRP Analysis

Detects HTTP traffic over TCP port `5985` and extracts matching TCP streams for easier inspection of WinRM / PowerShell Remoting activity.

### Credential & Secret Hunting

Searches packet data for common authentication and secret-related patterns such as:

- `password`
- `username`
- `login`
- `Authorization: Basic`
- `Authorization: Bearer`
- API keys
- Access tokens
- Refresh tokens
- Session IDs
- CSRF tokens
- Cookies

Matching packet data is written to a separate report for investigation.

### Pattern Hunting

SimplePCAP also performs best-effort string extraction for:

- URLs
- Email addresses
- Base64-like strings
- JWT-like tokens
- THM-style flags

### TCP Port Discovery

TCP SYN/ACK packets are inspected to create a list of possible open TCP ports observed in the capture.

---

## Requirements

SimplePCAP is intended for Linux environments.

Required:

- Bash
- TShark / Wireshark CLI tools

The script also uses common Unix utilities such as:

- `awk`
- `grep`
- `sort`
- `strings`
- `xxd`
- `base64`

On Debian/Ubuntu systems, TShark can typically be installed with:

```bash
sudo apt update
sudo apt install tshark
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/bellurm/SimplePCAP.git
cd SimplePCAP
```

Make the script executable:

```bash
chmod +x find_credentials_pcap.sh
```

---

## Usage

Run SimplePCAP against a packet capture:

```bash
./find_credentials_pcap.sh trace.pcap
```

The script creates a dedicated output directory based on the capture name.

For example:

```text
trace.pcap
```

produces:

```text
pcap_loot_trace/
```

---

## Output

Depending on the traffic available in the capture, SimplePCAP creates reports such as:

```text
pcap_loot_trace/
├── dns.txt
├── flags_guess.txt
├── ftp.txt
├── generic_creds.txt
├── http.txt
├── http_cookies.txt
├── kerberos.txt
├── kerberos_asrep_hashes.txt
├── ntlm.txt
├── ntlm_hashes.txt
├── patterns.txt
├── ports.txt
├── successful_logins.txt
├── summary.txt
└── winrm_streams.txt
```

### `summary.txt`

Provides a quick overview of the artifacts found during analysis, including counts for:

- Possible TCP ports
- HTTP traffic
- HTTP cookies
- FTP activity
- NTLM authentication
- NetNTLMv2 material
- Kerberos traffic
- AS-REP material
- DNS queries
- Generic keyword matches
- WinRM streams
- Flag patterns

### `successful_logins.txt`

Contains authentication activity that SimplePCAP considers successfully used based on protocol-specific heuristics.

### `patterns.txt`

Contains strings that may be useful during manual investigation, including URLs, emails, Base64-like data, and JWT-like patterns.

---

## Why SimplePCAP?

Wireshark and TShark provide extremely powerful packet analysis capabilities, but manually searching through large captures can take time.

SimplePCAP does not attempt to replace Wireshark.

Instead, it acts as a first-pass triage utility that automatically extracts potentially interesting artifacts and organizes them into readable reports.

A typical workflow is:

```text
PCAP
  │
  ▼
SimplePCAP
  │
  ├── HTTP / Sessions
  ├── FTP
  ├── NTLM
  ├── Kerberos
  ├── DNS
  ├── WinRM
  ├── Credentials / Tokens
  └── Pattern Hunting
  │
  ▼
Focused manual analysis
```

---

## Use Cases

SimplePCAP can be useful for:

- Network traffic analysis
- Security labs
- CTF challenges
- DFIR practice
- Protocol analysis
- Credential exposure investigation
- Network troubleshooting
- Packet capture triage

---

## Limitations

SimplePCAP uses protocol fields, pattern matching, and heuristics.

Results should therefore be treated as investigation leads rather than definitive findings.

Encrypted traffic may prevent extraction of application-layer content, and some protocol fields may vary depending on the TShark version and the contents of the capture.

For deeper analysis, suspicious findings should be validated using Wireshark, TShark, or other appropriate forensic tools.

---

## Security & Responsible Use

This project is intended for educational, defensive security, CTF, laboratory, and authorized analysis purposes.

Only analyze packet captures and network traffic that you own or have explicit permission to inspect.

---

## Author

**Cyber Worm**

GitHub: [@bellurm](https://github.com/bellurm)
