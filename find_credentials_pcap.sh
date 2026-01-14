#!/usr/bin/env bash
#
# find_credentials_pcap.sh - Simple pcap loot tool
# - Everything about HTTP:    http.txt
# - Everything about FTP :    ftp.txt
# - Everything about NTLM:    ntlm.txt
# - Everything about DNS :    dns.txt
# - Summary              :    summary.txt
#
# Usage:
#   ./find_credentials_pcap.sh trace.pcap
#

set -euo pipefail

usage() {
  echo "Usage: $0 <pcap_file>"
  exit 1
}

if [[ $# -lt 1 ]]; then
  usage
fi

PCAP="$1"
if [[ ! -f "$PCAP" ]]; then
  echo "[!] Pcap None: $PCAP" >&2
  exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "[!] tshark couldn't found: sudo apt install tshark" >&2
  exit 1
fi

BASENAME="$(basename "$PCAP")"
BASENAME_NOEXT="${BASENAME%.*}"
OUTDIR="pcap_loot_${BASENAME_NOEXT}"
mkdir -p "$OUTDIR"

HTTP_TXT="$OUTDIR/http.txt"
FTP_TXT="$OUTDIR/ftp.txt"
NTLM_TXT="$OUTDIR/ntlm.txt"
DNS_TXT="$OUTDIR/dns.txt"
SUMMARY_TXT="$OUTDIR/summary.txt"

echo "[+] Pcap:   $PCAP"
echo "[+] Output: $OUTDIR"
echo "[+] Tshark: $(tshark -v | head -n1)"

########################################
# HTTP
########################################
echo "[+] HTTP..."
> "$HTTP_TXT"

echo "==========================" >> "$HTTP_TXT"
echo " HTTP REQUESTS (GET/POST)" >> "$HTTP_TXT"
echo "==========================" >> "$HTTP_TXT"

# Simple HTTP request list
tshark -r "$PCAP" \
  -Y "http.request" \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e http.request.method \
  -e http.host \
  -e http.request.uri \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  NF >= 6 {
    frame=$1; src=$2; dst=$3; method=$4; host=$5; uri=$6;
    if (host == "") host="-";
    if (uri == "") uri="/";
    printf "[#%s] %s -> %s  %s http://%s%s\n", frame, src, dst, method, host, uri;
  }
' >> "$HTTP_TXT"

echo "" >> "$HTTP_TXT"
echo "==========================" >> "$HTTP_TXT"
echo " HTTP POST BODY" >> "$HTTP_TXT"
echo "==========================" >> "$HTTP_TXT"

# HTTP POST body (form data)
tshark -r "$PCAP" \
  -Y 'http.request.method == "POST"' \
  -o "http.desegment_body:TRUE" \
  -o "tcp.desegment_tcp_streams:TRUE" \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e http.host \
  -e http.request.uri \
  -e http.content_type \
  -e http.file_data \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  NF >= 7 {
    frame=$1; src=$2; dst=$3; host=$4; uri=$5; ctype=$6; data=$7;
    if (host == "") host="-";
    if (uri == "") uri="/";
    printf "\n[Frame #%s] %s -> %s\n", frame, src, dst;
    printf "  URL: http://%s%s\n", host, uri;
    printf "  Content-Type: %s\n", (ctype==""?"-":ctype);
    printf "  Body:\n    %s\n", (data==""?"(boş)":data);
  }
' >> "$HTTP_TXT"

echo "" >> "$HTTP_TXT"
echo "==========================" >> "$HTTP_TXT"
echo " HTTP AUTHORIZATION HEADER" >> "$HTTP_TXT"
echo "==========================" >> "$HTTP_TXT"

# HTTP Authorization headers and Basic decode
tshark -r "$PCAP" \
  -Y "http.authorization" \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e http.host \
  -e http.request.uri \
  -e http.authorization \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  function trimq(s) {
    gsub(/^"|"$/, "", s); return s;
  }
  NF >= 6 {
    frame=$1; src=$2; dst=$3; host=$4; uri=$5; auth=$6;
    host=trimq(host); uri=trimq(uri); auth=trimq(auth);
    split(auth, a, " ");
    scheme=a[1]; b64=a[2];
    printf "\n[Frame #%s] %s -> %s\n", frame, src, dst;
    printf "  URL: http://%s%s\n", (host==""?"-":host), (uri==""?"/":uri);
    printf "  Authorization: %s\n", auth;
    if (scheme == "Basic" && b64 != "") {
      cmd = "echo " b64 " | base64 -d 2>/dev/null";
      cmd | getline dec; close(cmd);
      if (dec != "") {
        printf "  Decoded (Basic): %s\n", dec;
      }
    }
  }
' >> "$HTTP_TXT"

echo "" >> "$HTTP_TXT"
echo "==========================" >> "$HTTP_TXT"
echo " VISITED URLs" >> "$HTTP_TXT"
echo "==========================" >> "$HTTP_TXT"

tshark -r "$PCAP" \
  -Y "http.request" \
  -T fields \
  -e http.host \
  -e http.request.uri \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  NF >= 2 {
    host=$1; uri=$2;
    if (host == "") next;
    if (uri == "") uri="/";
    print "http://" host uri;
  }
' | sort -u >> "$HTTP_TXT"

echo "    -> $HTTP_TXT"

########################################
# FTP
########################################
echo "[+] FTP..."
> "$FTP_TXT"

echo "==================" >> "$FTP_TXT"
echo " FTP COMMANDS"     >> "$FTP_TXT"
echo "==================" >> "$FTP_TXT"

tshark -r "$PCAP" \
  -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e ftp.request.command \
  -e ftp.request.arg \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  NF >= 6 {
    frame=$1; t=$2; src=$3; dst=$4; cmd=$5; arg=$6;
    printf "[Frame #%s] %s -> %s  %-4s %s\n", frame, src, dst, cmd, arg;
  }
' >> "$FTP_TXT"

echo "    -> $FTP_TXT"

########################################
# NTLM (SMB/HTTP)
########################################
echo "[+] NTLM..."
> "$NTLM_TXT"

echo "===================" >> "$NTLM_TXT"
echo " NTLM AUTH" >> "$NTLM_TXT"
echo "===================" >> "$NTLM_TXT"

tshark -r "$PCAP" \
  -Y "ntlmssp.auth.username" \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e ntlmssp.auth.domain \
  -e ntlmssp.auth.username \
  -e ntlmssp.auth.host \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  NF >= 7 {
    frame=$1; t=$2; src=$3; dst=$4; dom=$5; user=$6; host=$7;
    dom=(dom==""?"-":dom);
    host=(host==""?"-":host);
    printf "[Frame #%s] %s -> %s  DOMAIN: %s  USER: %s  HOST: %s\n", frame, src, dst, dom, user, host;
  }
' >> "$NTLM_TXT"

echo "    -> $NTLM_TXT"

########################################
# DNS
########################################
echo "[+] DNS..."
> "$DNS_TXT"

echo "==================" >> "$DNS_TXT"
echo " DNS QUERIES"       >> "$DNS_TXT"
echo "==================" >> "$DNS_TXT"

tshark -r "$PCAP" \
  -Y "dns.flags.response == 0" \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e dns.qry.name \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  NF >= 4 {
    frame=$1; t=$2; src=$3; name=$4;
    printf "[Frame #%s] %s  %s\n", frame, src, name;
  }
' >> "$DNS_TXT"

echo "    -> $DNS_TXT"

########################################
# ÖZET
########################################
echo "[+] Summary..."
> "$SUMMARY_TXT"

echo "PCAP: $PCAP" >> "$SUMMARY_TXT"
echo "Output dir: $OUTDIR" >> "$SUMMARY_TXT"
echo "" >> "$SUMMARY_TXT"

echo "[HTTP] $(grep -c '^\\[#' \"$HTTP_TXT\" || true) line (include request/post/auth/url)" >> "$SUMMARY_TXT"
echo "[FTP ] $(grep -c '^\\[Frame' \"$FTP_TXT\" || true) line" >> "$SUMMARY_TXT"
echo "[NTLM] $(grep -c '^\\[Frame' \"$NTLM_TXT\" || true) line" >> "$SUMMARY_TXT"
echo "[DNS ] $(grep -c '^\\[Frame' \"$DNS_TXT\" || true) line" >> "$SUMMARY_TXT"

echo "    -> $SUMMARY_TXT"
echo "[+] DONE."
