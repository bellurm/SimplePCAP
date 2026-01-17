#!/usr/bin/env bash

# Usage:
#   ./find_credentials_pcap.sh trace.pcap


set -euo pipefail

usage() {
  echo "Usage: $0 <pcap*_file>"
  exit 1
}

if [[ $# -lt 1 ]]; then
  usage
fi

PCAP="$1"
if [[ ! -f "$PCAP" ]]; then
  echo "[!] There is no: $PCAP" >&2
  exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "[!] Tshark couldn't find: sudo apt install tshark" >&2
  exit 1
fi

BASENAME="$(basename "$PCAP")"
BASENAME_NOEXT="${BASENAME%.*}"
OUTDIR="pcap_loot_${BASENAME_NOEXT}"
mkdir -p "$OUTDIR"

HTTP_TXT="$OUTDIR/http.txt"
HTTP_COOKIE_TXT="$OUTDIR/http_cookies.txt"
FTP_TXT="$OUTDIR/ftp.txt"
NTLM_TXT="$OUTDIR/ntlm.txt"
DNS_TXT="$OUTDIR/dns.txt"
GENERIC_TXT="$OUTDIR/generic_creds.txt"
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
# HTTP Cookie / Session
########################################
echo "[+] HTTP cookie / session bilgileri çıkarılıyor..."
> "$HTTP_COOKIE_TXT"

echo "==========================" >> "$HTTP_COOKIE_TXT"
echo " HTTP COOKIE / SET-COOKIE" >> "$HTTP_COOKIE_TXT"
echo "==========================" >> "$HTTP_COOKIE_TXT"

tshark -r "$PCAP" \
  -Y "http.cookie || http.set_cookie" \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e http.host \
  -e http.request.uri \
  -e http.cookie \
  -e http.set_cookie \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  NF >= 7 {
    frame=$1; src=$2; dst=$3; host=$4; uri=$5; cookie=$6; setcookie=$7;
    if (host == "") host="-";
    if (uri == "") uri="/";
    if (cookie == "" && setcookie == "") next;
    printf "\n[Frame #%s] %s -> %s\n", frame, src, dst;
    printf "  URL: http://%s%s\n", host, uri;
    if (cookie != "")    printf "  Cookie: %s\n", cookie;
    if (setcookie != "") printf "  Set-Cookie: %s\n", setcookie;
  }
' >> "$HTTP_COOKIE_TXT"

echo "    -> $HTTP_COOKIE_TXT"

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
' >> "$FTP_TXT" || true

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
' >> "$NTLM_TXT" || true

echo "    -> $NTLM_TXT"

########################################
# DNS
########################################
echo "[+] DNS ..."
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
' >> "$DNS_TXT" || true

echo "    -> $DNS_TXT"

########################################
# General keyword hunting
########################################
echo "[+] Keyword hunting (password/token/cookie etc.)..."
> "$GENERIC_TXT"

echo "==========================" >> "$GENERIC_TXT"
echo " GENERAL KEYWORD MATCHES" >> "$GENERIC_TXT"
echo "==========================" >> "$GENERIC_TXT"

KEYWORDS=(
  "password"
  "passwd="
  "pwd="
  "pass="
  "login="
  "user="
  "username="
  "uname="
  "email="
  "mail="
  "User:"
  "Pass:"
  "Login:"
  "auth="
  "Authorization: Basic"
  "Authorization: Bearer"
  "bearer "
  "Bearer "
  "token="
  "access_token"
  "refresh_token"
  "id_token"
  "apikey"
  "api_key"
  "key="
  "session"
  "sessionid"
  "session_id"
  "sid="
  "csrftoken"
  "X-CSRF-Token"
  "Set-Cookie:"
  "Cookie:"
)

for kw in "${KEYWORDS[@]}"; do
  echo "" >> "$GENERIC_TXT"
  echo "------------------------------" >> "$GENERIC_TXT"
  echo " PATTERN: $kw" >> "$GENERIC_TXT"
  echo "------------------------------" >> "$GENERIC_TXT"

  tshark -r "$PCAP" \
    -Y "frame contains \"$kw\"" \
    -T fields \
    -e frame.number \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e data.text \
    -e data.data \
    -E header=n \
    -E separator=$'\t' \
    -E quote=n \
    -E occurrence=f 2>/dev/null \
  | awk -F'\t' -v kw="$kw" '
      NF >= 4 {
        frame=$1; t=$2; src=$3; dst=$4;
        txt=$5; hex=$6;

        if (txt == "") txt="-";
        if (hex == "") hex="-";

        # Hex -> ASCII decode denemesi (xxd lazim)
        dec = "-";
        if (hex != "-" && hex != "") {
          # Hex olmayan karakterleri temizle (boşluk, : vs.)
          gsub(/[^0-9A-Fa-f]/, "", hex);
          if (hex != "") {
            cmd = "echo " hex " | xxd -r -p 2>/dev/null";
            cmd | getline dec;
            close(cmd);
            if (dec == "") dec = "-";
          }
        }

        printf "[Frame #%s] t=%s %s -> %s\n", frame, t, src, dst;
        printf "  Data.text: %s\n", txt;
        printf "  Data.hex : %s\n", hex;
        printf "  Data.hex-ascii: %s\n", dec;
      }
    ' >> "$GENERIC_TXT" || true
done

echo "    -> $GENERIC_TXT"

########################################
# SUMMARY
########################################
echo "[+] SUMMARY..."
> "$SUMMARY_TXT"

{
  echo "PCAP: $PCAP"
  echo "Output dir: $OUTDIR"
  echo ""
  echo "[HTTP        ] $(grep -c '^\[#'      "$HTTP_TXT"        2>/dev/null) lines"
  echo "[HTTP Cookie ] $(grep -c '^\[Frame' "$HTTP_COOKIE_TXT" 2>/dev/null) lines"
  echo "[FTP         ] $(grep -c '^\[Frame' "$FTP_TXT"         2>/dev/null) lines"
  echo "[NTLM        ] $(grep -c '^\[Frame' "$NTLM_TXT"        2>/dev/null) lines"
  echo "[DNS         ] $(grep -c '^\[Frame' "$DNS_TXT"         2>/dev/null) lines"
  echo "[GENERIC KW  ] $(grep -c '^\[Frame' "$GENERIC_TXT"     2>/dev/null) lines"
} >> "$SUMMARY_TXT"

echo "    -> $SUMMARY_TXT"
echo "[+] Done."
