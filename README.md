# secrets-scanner
#### 📌 Overview

A comprehensive automated pipeline for discovering secrets, tokens, and sensitive information across web applications using multiple attack vectors and reconnaissance techniques.

#### 🚀 **Features**

- **Multi-Vector Scanning:** Combines subdomain enumeration, port scanning, HTTP discovery, and secrets detection
- **JavaScript Analysis:** Deep analysis of JavaScript files from both live hosts and Wayback Machine
- **Historical Data Mining:** Leverages Wayback Machine for finding exposed secrets in historical JS files
- **Advanced Secret Detection:** Uses multiple tools (Nuclei, TruffleHog) for comprehensive coverage
- **Automated Workflow:** End-to-end automation from domain input to detailed reporting
- **Professional Logging:** Color-coded output with detailed logging and progress tracking
- **Error Resilience:** Robust error handling and graceful failure recovery

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
katana -u root.txt -ps -em js,json -o kwa.txt && httpx -l kwa.txt -mc 200 -o wa_js_alive.txt && nuclei -l wa_js_alive.txt -tags token,tokens -es unknown -rl 1000 -c 100 -o nuclei_wayback_secrets.txt
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
   - `katana` -> `go install -v github.com/projectdiscovery/katana/cmd/katana@v1.1.0` // Version with Passive Source Support
   - `trufflehog`

2. Prepare a text file (`root.txt`) containing your target domains, one per line.
3. Run the script:
```bash
chmod +x advanced-secrets-scanner.sh && bash advanced-secrets-scanner.sh -f root.txt
```

#### 📁 Output Structure
```bash
results/
├── scan_YYYYMMDD_HHMMSS.log          # Detailed execution log
├── subs.txt                          # Discovered subdomains
├── naabu.txt                         # Open ports
├── alive_http_services.txt           # Live HTTP services
├── nuclei/
│   ├── nuclei_hosts_secrets.txt      # Secrets found on hosts
│   ├── nuclei_js_secrets.txt         # Secrets found in JS files
│   └── nuclei_wayback_secrets.txt    # Secrets found in Wayback JS
├── js/
│   └── js.txt                        # Collected JavaScript files
├── wayback/
│   ├── kwa.txt                       # Wayback URLs
│   └── wa_js_alive.txt              # Live Wayback JS files
├── responses/                        # Downloaded JS files for analysis
└── trufflehog_results.txt           # TruffleHog findings
```

#### 🎨 Sample Output
```bash
[SUCCESS] Scan completed! Generating summary report...

==================================
    SECRETS SCAN SUMMARY REPORT
==================================

📊 Scan Statistics:
  • Subdomains discovered: 696
  • Open ports found: 410
  • Live HTTP services: 17
  • JavaScript files collected: 32
  • Wayback JS files found: 1

🔍 Secrets Discovery Results:
  • Host-based secrets: 0 (nuclei/nuclei_hosts_secrets.txt)
  • JavaScript secrets: 0 (nuclei/nuclei_js_secrets.txt)
  • Wayback secrets: 0 (nuclei/nuclei_wayback_secrets.txt)
  • Trufflehog findings: 0 (trufflehog_results.txt)

🎯 Total potential secrets found: 0

📁 Output files location: /home/ec2-user/secrets-scanner/results
📝 Detailed log: scan_20250526_213737.log

[SUCCESS] Pipeline completed successfully with 0 total findings
```

#### 🧠 Use Case

Perfect for fast, repeatable audits during reconnaissance and early bug bounty phases. Can also be integrated into CI/CD pipelines for continuous monitoring of secret exposure.
