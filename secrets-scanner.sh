#!/bin/bash

# secrets-scanner pipeline with expanded JS and wayback analysis

# Default values
DOMAINS_FILE=""
SUBS="subs.txt"
NAABU_OUT="naabu.txt"
ALIVE_HTTP="alive_http_services.txt"
JS_FILES="js.txt"
KWA_OUT="kwa.txt"
WA_JS_ALIVE="wa_js_alive.txt"
JS_ALL="js_all.txt"
NUCLEI_HOSTS_SECRETS="nuclei_hosts_secrets.txt"
NUCLEI_JS_SECRETS="nuclei_js_secrets.txt"
NUCLEI_WAYBACK_SECRETS="nuclei_wayback_secrets.txt"
TRUFFLEHOG_RESULTS="trufflehog_results.txt"
RESPONSES_DIR="responses"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f|--file) DOMAINS_FILE="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [[ -z "$DOMAINS_FILE" ]]; then
    echo "Usage: $0 -f domains.txt"
    exit 1
fi

echo "[*] Running subdomain and host recon..."
subfinder -dL "$DOMAINS_FILE" -all -silent -o "$SUBS"
naabu -l "$SUBS" -s s -tp 100 -ec -c 50 -o "$NAABU_OUT"
httpx -l "$NAABU_OUT" -rl 500 -t 200 -o "$ALIVE_HTTP"

echo "[*] Scanning live hosts for secrets with Nuclei..."
nuclei -l "$ALIVE_HTTP" -tags token,tokens -es unknown -rl 1000 -c 100 -o "$NUCLEI_HOSTS_SECRETS"

echo "[*] Collecting JavaScript files from alive hosts..."
getJS -input "$ALIVE_HTTP" -output "$JS_FILES" -complete -threads 200

echo "[*] Scanning JS files with Nuclei..."
nuclei -l "$JS_FILES" -tags token,tokens -es unknown -rl 1000 -c 100 -o "$NUCLEI_JS_SECRETS"

echo "[*] Running wayback analysis with Katana..."
katana -u "$DOMAINS_FILE" -ps -em js,json -o "$KWA_OUT"
httpx -l "$KWA_OUT" -mc 200 -o "$WA_JS_ALIVE"
nuclei -l "$WA_JS_ALIVE" -tags token,tokens -es unknown -rl 1000 -c 100 -o "$NUCLEI_WAYBACK_SECRETS"

echo "[*] Running Trufflehog on combined JS sources..."
rm -rf "$RESPONSES_DIR"
cat "$JS_FILES" "$WA_JS_ALIVE" | sort -u > "$JS_ALL"
httpx -l "$JS_ALL" -sr -srd "$RESPONSES_DIR"
trufflehog filesystem "$RESPONSES_DIR" > "$TRUFFLEHOG_RESULTS"

echo "[✔] Scan complete. Results:"
echo " - Host secrets: $NUCLEI_HOSTS_SECRETS ($(wc -l < "$NUCLEI_HOSTS_SECRETS") lines)"
echo " - JS secrets: $NUCLEI_JS_SECRETS ($(wc -l < "$NUCLEI_JS_SECRETS") lines)"
echo " - Wayback secrets: $NUCLEI_WAYBACK_SECRETS ($(wc -l < "$NUCLEI_WAYBACK_SECRETS") lines)"
echo " - Trufflehog output: $TRUFFLEHOG_RESULTS ($(wc -l < "$TRUFFLEHOG_RESULTS") lines)"
