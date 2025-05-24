# secrets-scanner
#### 📌 Overview

Secrets-scanner is an automated pipeline designed to discover secret leaks in JavaScript files from live web assets identified during reconnaissance. This tool is ideal for security researchers and bug bounty hunters looking to streamline their secret detection process.

#### 🚀 Recon (Reconnaissance)

The process begins with domain and port scanning, followed by identification of live HTTP services:
```
subfinder -dL root.txt -all -silent -o subs.txt && \
naabu -l subs.txt -s s -tp 100 -ec -c 50 -o naabu.txt && \
httpx -l naabu.txt -rl 500 -t 200 -o alive_http_services.txt
```
#### JavaScript File Collection

Next, JavaScript files are extracted from the live HTTP services:
```
getJS -input alive_http_services.txt -output js.txt -complete -threads 200
```
#### Secret Detection with Nuclei

Nuclei is used to scan the JavaScript files for exposed tokens and other sensitive information:
```
nuclei -l js.txt -tags token,tokens -es unknown -rl 1000 -c 100 -o nuclei_secrets.txt
```
#### Trufflehog Analysis

The JavaScript files are downloaded and analyzed using Trufflehog to find potential secret leaks:
```
rm -rf responses/ && \
httpx -l js.txt -sr -srd responses/ && \
trufflehog filesystem responses/ > trufflehog_results.txt
```

#### 🧠 Use Case

Perfect for fast, repeatable audits during reconnaissance and early bug bounty phases. Can also be integrated into CI/CD pipelines for continuous monitoring of secret exposure.
