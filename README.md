# secrets-scanner
#### 📌 Overview

Secrets-scanner is an automated pipeline designed to discover secret leaks in JavaScript files from live web assets identified during reconnaissance. This tool is ideal for security researchers and bug bounty hunters looking to streamline their secret detection process.

#### 🚀 Recon (Reconnaissance)

The process begins with domain and port scanning, followed by identification of live HTTP services:
```bash
subfinder -dL root.txt -all -silent -o subs.txt && \
naabu -l subs.txt -s s -tp 100 -ec -c 50 -o naabu.txt && \
httpx -l naabu.txt -rl 500 -t 200 -o alive_http_services.txt
```
#### Hosts Scanning
```bash
nuclei -l alive_http_services.txt -tags token,tokens -es unknown -rl 1000 -c 100 -o nuclei_hosts_secrets.txt
```
#### JavaScript File Collection

Next, JavaScript files are extracted from the live HTTP services:
```bash
getJS -input alive_http_services.txt -output js.txt -complete -threads 200
```
#### Secret Detection with Nuclei

Nuclei is used to scan the JavaScript files for exposed tokens and other sensitive information:
```bash
nuclei -l js.txt -tags token,tokens -es unknown -rl 1000 -c 100 -o nuclei_js_secrets.txt
```
#### Secret Detection with Katana and Nuclei

```bash
katana -u root.txt -ps -ef js,json -o kwa.txt && httpx -l kwa.txt -mc 200 -o wa_js_alive.txt && nuclei -l wa_js_alive.txt -tags token,tokens -es unknown -rl 1000 -c 100 -o nuclei_wayback_secrets.txt
```

#### Trufflehog Analysis

The JavaScript files are downloaded and analyzed using Trufflehog to find potential secret leaks:
```bash
rm -rf responses/ && \
cat js.txt wa_js_alive.txt | sort -u > js_all.txt && \
httpx -l js_all.txt -sr -srd responses/ && \
trufflehog filesystem responses/ > trufflehog_results.txt
```
---

#### Secrets-Scanner Script

1. Make sure the following tools are installed and available in your `$PATH`:

   - `subfinder`
   - `naabu`
   - `httpx`
   - `getJS`
   - `nuclei`
   - `katana` version 1.1.0 with passive source support
   - `trufflehog`

2. Prepare a text file (`root.txt`) containing your target domains, one per line.
3. Run the script:
```bash
chmod +x secrets-scanner.sh && bash secrets-scanner.sh -f root.txt
```
4. Scan results will be saved to the following files:

- `nuclei_hosts_secrets.txt` – secrets detected in live hosts
- `nuclei_js_secrets.txt` – secrets found in JavaScript files
- `nuclei_wayback_secrets.txt` – secrets discovered JavaScript files via wayback analysis
- `trufflehog_results.txt` – secrets extracted by Trufflehog from all collected JS content

#### 🧠 Use Case

Perfect for fast, repeatable audits during reconnaissance and early bug bounty phases. Can also be integrated into CI/CD pipelines for continuous monitoring of secret exposure.
