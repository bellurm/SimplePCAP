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
NTLM_HASHES_TXT="$OUTDIR/ntlm_hashes.txt"
DNS_TXT="$OUTDIR/dns.txt"
GENERIC_TXT="$OUTDIR/generic_creds.txt"
SUMMARY_TXT="$OUTDIR/summary.txt"
SUCCESS_TXT="$OUTDIR/successful_logins.txt"
PATTERN_TXT="$OUTDIR/patterns.txt"
KRB_TXT="$OUTDIR/kerberos.txt"
KRB_ASREP_TXT="$OUTDIR/kerberos_asrep_hashes.txt"
PORTS_TXT="$OUTDIR/ports.txt"
WINRM_TXT="$OUTDIR/winrm_streams.txt"
FLAG_TXT="$OUTDIR/flags_guess.txt"

echo "[+] Pcap:   $PCAP"
echo "[+] Output: $OUTDIR"
echo "[+] Tshark: $(tshark -v | head -n1)"

# Global successful/used credentials summary (heuristic)
> "$SUCCESS_TXT"
echo "==========================" >> "$SUCCESS_TXT"
echo " SUCCESSFUL / USED CREDENTIALS (heuristic)" >> "$SUCCESS_TXT"
echo "==========================" >> "$SUCCESS_TXT"

########################################
# TCP SYN/ACK -> muhtemel açık portlar
########################################
echo "[+] TCP SYN/ACK port özeti..."
> "$PORTS_TXT"

echo "==========================" >> "$PORTS_TXT"
echo " POSSIBLE OPEN TCP PORTS" >> "$PORTS_TXT"
echo "==========================" >> "$PORTS_TXT"

tshark -r "$PCAP" \
  -Y "tcp.flags.syn == 1 && tcp.flags.ack == 1" \
  -T fields -e tcp.dstport 2>/dev/null \
| sort -nu >> "$PORTS_TXT" || true

echo "    -> $PORTS_TXT"

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
| awk -F'\t' -v succ="$SUCCESS_TXT" '
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
        # Kullanılan HTTP Basic credential’ı özet dosyasına yaz
        printf "HTTP_BASIC\t%s\thttp://%s%s\n",
               dec,
               (host==""?"-":host),
               (uri==""?"/":uri) >> succ;
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

# Önce USER/PASS komutlarını listeleyelim
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

echo "" >> "$FTP_TXT"
echo "==========================" >> "$FTP_TXT"
echo " FTP SUCCESSFUL LOGINS (heuristic)" >> "$FTP_TXT"
echo "==========================" >> "$FTP_TXT"

# Burada FTP response code 230 (Login successful) üzerinden
# TÜM başarılı login’leri tespit ediyoruz.
FTP_SUCCESS_LINE="$(
  tshark -r "$PCAP" \
    -Y "ftp" \
    -T fields \
    -e frame.number \
    -e tcp.stream \
    -e ip.src \
    -e ip.dst \
    -e ftp.request.command \
    -e ftp.request.arg \
    -e ftp.response.code \
    -e ftp.response.arg \
    -E header=n \
    -E separator=$'\t' \
    -E quote=n \
    -E occurrence=f 2>/dev/null \
  | awk -F'\t' -v succ="$SUCCESS_TXT" '
      {
        frame=$1; stream=$2; src=$3; dst=$4;
        cmd=$5; arg=$6; code=$7; rarg=$8;

        # Stream bazlı son USER/PASS değerlerini tut
        if (cmd == "USER" && arg != "") {
          user[stream] = arg;
        } else if (cmd == "PASS" && arg != "") {
          pass[stream] = arg;
        }

        # 230 -> successful login
        if (code == "230") {
          u = (stream in user ? user[stream] : "?");
          p = (stream in pass ? pass[stream] : "?");
          line = sprintf("[SUCCESS] stream=%s frame=%s %s -> %s USER=%s PASS=%s (%s)",
                         stream, frame, src, dst, u, p, rarg);
          print line;                               # stdout (tee için)
          printf "FTP\t%s\t%s\t%s->%s\tstream=%s\tframe=%s\n",
                 u, p, src, dst, stream, frame >> succ;  # global başarı dosyası
        }
      }
    ' \
  | tee -a "$FTP_TXT" \
  | head -n1 \
  || true
)"

echo "    -> $FTP_TXT"

if [[ -n "$FTP_SUCCESS_LINE" ]]; then
  echo "[+] FTP first successful login (heuristic): $FTP_SUCCESS_LINE"
fi

########################################
# NTLM (SMB/HTTP) + netntlmv2 hash
########################################
echo "[+] NTLM..."
> "$NTLM_TXT"
> "$NTLM_HASHES_TXT"

echo "===================" >> "$NTLM_TXT"
echo " NTLM AUTH"         >> "$NTLM_TXT"
echo "===================" >> "$NTLM_TXT"

# İnsan okunur özet
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
    printf "[Frame #%s] t=%s %s -> %s  DOMAIN: %s  USER: %s  HOST: %s\n",
           frame, t, src, dst, dom, user, host;
  }
' >> "$NTLM_TXT" || true

echo "" >> "$NTLM_TXT"
echo "    -> $NTLM_TXT"

echo "===================" >> "$NTLM_HASHES_TXT"
echo " netntlmv2 hashes (user::domain:server_challenge:ntlmv2_response)" >> "$NTLM_HASHES_TXT"
echo "===================" >> "$NTLM_HASHES_TXT"

# netntlmv2 hash formatı üret (hashcat -m 5600 / john --format=netntlmv2)
tshark -r "$PCAP" \
  -Y "ntlmssp" \
  -T fields \
  -e tcp.stream \
  -e ntlmssp.ntlmserverchallenge \
  -e ntlmssp.auth.domain \
  -e ntlmssp.auth.username \
  -e ntlmssp.ntlmv2_response \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' -v out="$NTLM_HASHES_TXT" '
  {
    stream = $1
    chall  = $2
    dom    = $3
    user   = $4
    resp   = $5

    # CHALLENGE frame’leri
    if (chall != "") {
      gsub(":", "", chall)         # 01:23:45 -> 012345...
      challenge[stream] = chall
    }

    # AUTH frame’leri (username + ntlmv2_response)
    if (user != "" && resp != "") {
      c = challenge[stream]
      if (c != "") {
        printf "%s::%s:%s:%s\n", user, dom, c, resp >> out
      }
    }
  }
'

echo "    -> $NTLM_HASHES_TXT"

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
# Kerberos (AS-REQ / AS-REP / TGS)
########################################
echo "[+] Kerberos..."
> "$KRB_TXT"
> "$KRB_ASREP_TXT"

echo "==========================" >> "$KRB_TXT"
echo " KERBEROS MSGS"           >> "$KRB_TXT"
echo "==========================" >> "$KRB_TXT"

tshark -r "$PCAP" \
  -Y "kerberos" \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e kerberos.msg_type \
  -e kerberos.realm \
  -e kerberos.CNameString \
  -e kerberos.etype \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' '
  NF >= 8 {
    frame=$1; t=$2; src=$3; dst=$4; msg=$5; realm=$6; cname=$7; etype=$8;
    if (realm == "") realm="-";
    if (cname == "") cname="-";
    printf "[Frame #%s] t=%s %s -> %s  msg_type=%s realm=%s user=%s etype=%s\n",
           frame, t, src, dst, msg, realm, cname, etype;
  }
' >> "$KRB_TXT" || true

echo "    -> $KRB_TXT"

echo "==========================" >> "$KRB_ASREP_TXT"
echo " KRB5 AS-REP hashes (\$krb5asrep\$) (etype 23 + cipher varsa)" >> "$KRB_ASREP_TXT"
echo "==========================" >> "$KRB_ASREP_TXT"

# Not: Bazı tshark versiyonlarında kerberos.cipher boş gelebilir (o durumda hash üretilmez).
tshark -r "$PCAP" \
  -Y "kerberos.msg_type == 11 && kerberos.CNameString && kerberos.cipher && kerberos.etype == 23" \
  -T fields \
  -e kerberos.realm \
  -e kerberos.CNameString \
  -e kerberos.etype \
  -e kerberos.cipher \
  -E header=n \
  -E separator=$'\t' \
  -E quote=n \
  -E occurrence=f 2>/dev/null \
| awk -F'\t' -v out="$KRB_ASREP_TXT" '
  NF >= 4 {
    realm = toupper($1);
    user  = $2;
    etype = $3;
    cipher = $4;

    # hex dışında her şeyi temizle
    gsub(/[^0-9A-Fa-f]/, "", cipher);
    if (cipher == "") next;

    checksum = substr(cipher, 1, 32);
    enc      = substr(cipher, 33);

    printf "$krb5asrep$%s$%s@%s:%s$%s\n", etype, user, realm, checksum, enc >> out;
  }
'

echo "    -> $KRB_ASREP_TXT"

########################################
# WinRM / PSRP (TCP 5985) stream dump
########################################
echo "[+] WinRM / PSRP (tcp/5985) stream'leri toplanıyor..."
> "$WINRM_TXT"

streams=$(tshark -r "$PCAP" \
  -Y "tcp.port == 5985 && http.request" \
  -T fields -e tcp.stream 2>/dev/null | sort -nu)

if [[ -n "${streams:-}" ]]; then
  {
    echo "=============================="
    echo " WINRM / PSRP TCP STREAMS"
    echo "=============================="
    echo "# Not: Her stream için 'follow,tcp,ascii' çıktısı aşağıdadır."
  } >> "$WINRM_TXT"

  for s in $streams; do
    echo "" >> "$WINRM_TXT"
    echo "===== STREAM $s =====" >> "$WINRM_TXT"
    tshark -q -r "$PCAP" -z "follow,tcp,ascii,$s" 2>/dev/null >> "$WINRM_TXT" || true
  done
fi

echo "    -> $WINRM_TXT"

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
# Strings-based pattern hunting (URL/email/base64/JWT)
########################################
echo "[+] Pattern hunting (URL/email/base64/JWT)..."
> "$PATTERN_TXT"

echo "==========================" >> "$PATTERN_TXT"
echo " STRINGS-BASED PATTERN HUNTING" >> "$PATTERN_TXT"
echo "==========================" >> "$PATTERN_TXT"

# 1) URL'ler
echo "" >> "$PATTERN_TXT"
echo "---------- URLs ----------" >> "$PATTERN_TXT"

strings "$PCAP" 2>/dev/null \
  | grep -Ei 'https?://[A-Za-z0-9._:/?#@%&=+,\-]+' \
  | sort -u >> "$PATTERN_TXT" || true

# 2) E-posta adresleri
echo "" >> "$PATTERN_TXT"
echo "-------- EMAILs ----------" >> "$PATTERN_TXT"

strings "$PCAP" 2>/dev/null \
  | grep -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
  | sort -u >> "$PATTERN_TXT" || true

# 3) Base64 benzeri stringler (muhtemel token / secret)
echo "" >> "$PATTERN_TXT"
echo "------ BASE64-ish --------" >> "$PATTERN_TXT"

strings "$PCAP" 2>/dev/null \
  | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$' \
  | sort -u >> "$PATTERN_TXT" || true

# 4) JWT benzeri (eyJ... . .... . .... )
echo "" >> "$PATTERN_TXT"
echo "--------- JWTs -----------" >> "$PATTERN_TXT"

strings "$PCAP" 2>/dev/null \
  | grep -E 'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*' \
  | sort -u >> "$PATTERN_TXT" || true

echo "    -> $PATTERN_TXT"

########################################
# THM-style flag pattern hunting
########################################
echo "[+] Flag pattern hunting (THM{...})..."
> "$FLAG_TXT"

echo "==========================" >> "$FLAG_TXT"
echo " THM-style flags (best-effort)" >> "$FLAG_TXT"
echo "==========================" >> "$FLAG_TXT"

# ASCII strings içinden
strings -a "$PCAP" 2>/dev/null \
  | grep -o 'THM{[^}]*}' \
  | sort -u >> "$FLAG_TXT" || true

# UTF-16LE (wide) strings içinden
strings -el "$PCAP" 2>/dev/null \
  | grep -o 'THM{[^}]*}' \
  | sort -u >> "$FLAG_TXT" || true

echo "    -> $FLAG_TXT"

########################################
# SUMMARY
########################################
echo "[+] SUMMARY..."
> "$SUMMARY_TXT"

{
  echo "PCAP: $PCAP"
  echo "Output dir: $OUTDIR"
  echo ""
  echo "[PORTS       ] $(grep -c '^[0-9]'      "$PORTS_TXT"       2>/dev/null) lines"
  echo "[HTTP        ] $(grep -c '^\[#'        "$HTTP_TXT"        2>/dev/null) lines"
  echo "[HTTP Cookie ] $(grep -c '^\[Frame'    "$HTTP_COOKIE_TXT" 2>/dev/null) lines"
  echo "[FTP         ] $(grep -c '^\[Frame'    "$FTP_TXT"         2>/dev/null) lines"
  echo "[NTLM        ] $(grep -c '^\[Frame'    "$NTLM_TXT"        2>/dev/null) lines"
  echo "[NTLM HASHES ] $(grep -c '::'          "$NTLM_HASHES_TXT" 2>/dev/null) lines"
  echo "[KERBEROS    ] $(grep -c '^\[Frame'    "$KRB_TXT"         2>/dev/null) lines"
  echo "[KRB AS-REP  ] $(grep -c '^\$krb5asrep' "$KRB_ASREP_TXT"  2>/dev/null) lines"
  echo "[DNS         ] $(grep -c '^\[Frame'    "$DNS_TXT"         2>/dev/null) lines"
  echo "[GENERIC KW  ] $(grep -c '^\[Frame'    "$GENERIC_TXT"     2>/dev/null) lines"
  echo "[WINRM       ] $(grep -c '^===== STREAM' "$WINRM_TXT"     2>/dev/null) streams"
  echo "[FLAGS       ] $(grep -c 'THM{'        "$FLAG_TXT"        2>/dev/null) hits"
  echo "[PATTERNS    ] $(grep -c '.'           "$PATTERN_TXT"     2>/dev/null) lines"
} >> "$SUMMARY_TXT"

echo "[+] Done."
