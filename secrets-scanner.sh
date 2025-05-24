#!/bin/bash

# secrets-scanner full pipeline

# Default values
DOMAINS_FILE=""
SUBS="subs.txt"
NAABU_OUT="naabu.txt"
ALIVE_HTTP="alive_http_services.txt"
JS_FILES="js.txt"
NUCLEI_RESULTS="nuclei_secrets.txt"
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

# Step 1: Reconnaissance
echo "[*] Running reconnaissance..."
subfinder -dL "$DOMAINS_FILE" -all -silent -o "$SUBS"
naabu -l "$SUBS" -s s -tp 100 -ec -c 50 -o "$NAABU_OUT"
httpx -l "$NAABU_OUT" -rl 500 -t 200 -o "$ALIVE_HTTP"

# Step 2: Get JavaScript files
echo "[*] Extracting JavaScript files..."
getJS -input "$ALIVE_HTTP" -output "$JS_FILES" -complete -threads 200

# Step 3: Scan for secrets with Nuclei
echo "[*] Scanning JS with Nuclei for secrets..."
nuclei -l "$JS_FILES" -tags token,tokens -es unknown -rl 1000 -c 100 -o "$NUCLEI_RESULTS"

# Step 4: Trufflehog analysis
echo "[*] Running Trufflehog scan..."
rm -rf "$RESPONSES_DIR"
httpx -l "$JS_FILES" -sr -srd "$RESPONSES_DIR"
trufflehog filesystem "$RESPONSES_DIR" > "$TRUFFLEHOG_RESULTS"

echo "[✔] Pipeline completed. Results saved to:"
echo " - $NUCLEI_RESULTS"
echo " - $TRUFFLEHOG_RESULTS"
