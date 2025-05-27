#!/bin/bash
# Enhanced secrets-scanner pipeline with expanded JS and wayback analysis
# Version 2.1 - Added headless crawling for comprehensive JS/JSON discovery

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DOMAINS_FILE=""
SUBS="subs.txt"
NAABU_OUT="naabu.txt"
ALIVE_HTTP="alive_http_services.txt"
JS_FILES="js.txt"
KWA_OUT="kwa.txt"
WA_JS_ALIVE="wa_js_alive.txt"
HEADLESS_CRAWL="katana_headless_crawl_results.txt"
JS_ALL="js_all.txt"
NUCLEI_HOSTS_SECRETS="nuclei_hosts_secrets.txt"
NUCLEI_JS_SECRETS="nuclei_js_secrets.txt"
NUCLEI_WAYBACK_SECRETS="nuclei_wayback_secrets.txt"
NUCLEI_HEADLESS_SECRETS="nuclei_headless_secrets_results.txt"
TRUFFLEHOG_RESULTS="trufflehog_results.txt"
RESPONSES_DIR="responses"
LOG_FILE="scan_$(date +%Y%m%d_%H%M%S).log"
VERBOSE=false
SKIP_WAYBACK=false
SKIP_HEADLESS=false

rm -f *.log

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Check if required tools are installed
check_dependencies() {
    local tools=("subfinder" "naabu" "httpx" "nuclei" "getJS" "katana" "trufflehog")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log "ERROR" "Missing required tools: ${missing_tools[*]}"
        log "INFO" "Please install missing tools before running the script"
        exit 1
    fi
    
    log "SUCCESS" "All required tools are installed"
}

# Function to handle cleanup on script exit
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "WARNING" "Script interrupted or failed with exit code $exit_code"
    fi
    log "INFO" "Cleanup completed"
}

# Set trap for cleanup
trap cleanup EXIT

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f|--file) DOMAINS_FILE="$2"; shift ;;
        -v|--verbose) VERBOSE=true ;;
        --skip-wayback) SKIP_WAYBACK=true ;;
        --skip-headless) SKIP_HEADLESS=true ;;
        -h|--help) 
            echo "Usage: $0 -f domains.txt [OPTIONS]"
            echo "Options:"
            echo "  -f, --file        Input file containing domains (required)"
            echo "  -v, --verbose     Enable verbose output"
            echo "  --skip-wayback    Skip wayback machine analysis"
            echo "  --skip-headless   Skip headless browser crawling"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *) 
            log "ERROR" "Unknown parameter passed: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
    shift
done

# Validate input
if [[ -z "$DOMAINS_FILE" ]]; then
    log "ERROR" "No domains file specified"
    echo "Usage: $0 -f domains.txt"
    exit 1
fi

if [[ ! -f "$DOMAINS_FILE" ]]; then
    log "ERROR" "Domains file '$DOMAINS_FILE' does not exist"
    exit 1
fi

# Check dependencies
check_dependencies

# Create output directory structure
rm -rf results/ && mkdir -p results/{nuclei,js,wayback,headless,responses}
cd results || exit 1

log "INFO" "Starting secrets scanning pipeline for $(wc -l < "../$DOMAINS_FILE") domains"
log "INFO" "Log file: $LOG_FILE"

# Step 1: Subdomain Discovery
log "INFO" "Step 1/8: Running subdomain discovery..."
if subfinder -dL "../$DOMAINS_FILE" -all -silent -o "$SUBS"; then
    subdomain_count=$(wc -l < "$SUBS")
    log "SUCCESS" "Found $subdomain_count subdomains"
else
    log "ERROR" "Subfinder failed"
    exit 1
fi

# Step 2: Port Scanning
log "INFO" "Step 2/8: Running port scan on $subdomain_count targets..."
if naabu -l "$SUBS" -s s -tp 100 -ec -c 50 -o "$NAABU_OUT" -silent; then
    port_count=$(wc -l < "$NAABU_OUT")
    log "SUCCESS" "Found $port_count open ports"
else
    log "ERROR" "Naabu failed"
    exit 1
fi

# Step 3: HTTP Service Discovery
log "INFO" "Step 3/8: Discovering live HTTP services..."
if httpx -l "$NAABU_OUT" -rl 500 -t 200 -o "$ALIVE_HTTP" -silent; then
    http_count=$(wc -l < "$ALIVE_HTTP")
    log "SUCCESS" "Found $http_count live HTTP services"
else
    log "ERROR" "Httpx failed"
    exit 1
fi

# Step 4: Direct Host Scanning
log "INFO" "Step 4/8: Scanning live hosts for secrets with Nuclei..."
if nuclei -l "$ALIVE_HTTP" -tags token,tokens -es unknown -rl 1000 -c 100 -o "nuclei/$NUCLEI_HOSTS_SECRETS" -silent; then
    host_secrets=$(wc -l < "nuclei/$NUCLEI_HOSTS_SECRETS" 2>/dev/null || echo "0")
    log "SUCCESS" "Host scan completed - found $host_secrets potential secrets"
else
    log "WARNING" "Nuclei host scan had issues but continuing..."
fi

# Step 5: JavaScript File Collection and Scanning
log "INFO" "Step 5/8: Collecting JavaScript files from alive hosts..."
if getJS -input "$ALIVE_HTTP" -output "js/$JS_FILES" -complete -threads 200; then
    js_count=$(wc -l < "js/$JS_FILES" 2>/dev/null || echo "0")
    log "SUCCESS" "Collected $js_count JavaScript files"
    
    if [ "$js_count" -gt 0 ]; then
        log "INFO" "Scanning JavaScript files with Nuclei..."
        if nuclei -l "js/$JS_FILES" -tags token,tokens -es unknown -rl 1000 -c 100 -o "nuclei/$NUCLEI_JS_SECRETS" -silent; then
            js_secrets=$(wc -l < "nuclei/$NUCLEI_JS_SECRETS" 2>/dev/null || echo "0")
            log "SUCCESS" "JS scan completed - found $js_secrets potential secrets"
        else
            log "WARNING" "Nuclei JS scan had issues but continuing..."
        fi
    fi
else
    log "WARNING" "getJS failed but continuing..."
fi

# Step 6: Wayback Analysis (optional)
if [ "$SKIP_WAYBACK" = false ]; then
    log "INFO" "Step 6/8: Running wayback analysis with Katana..."
    if katana -u "../$DOMAINS_FILE" -ps -em js,json -o "wayback/$KWA_OUT" -silent; then
        wayback_count=$(wc -l < "wayback/$KWA_OUT" 2>/dev/null || echo "0")
        log "SUCCESS" "Found $wayback_count wayback URLs"
        
        if [ "$wayback_count" -gt 0 ]; then
            log "INFO" "Filtering live wayback JavaScript files..."
            if httpx -l "wayback/$KWA_OUT" -mc 200 -o "wayback/$WA_JS_ALIVE" -silent; then
                wa_js_count=$(wc -l < "wayback/$WA_JS_ALIVE" 2>/dev/null || echo "0")
                log "SUCCESS" "Found $wa_js_count live wayback JS files"
                
                if [ "$wa_js_count" -gt 0 ]; then
                    log "INFO" "Scanning wayback JS files with Nuclei..."
                    if nuclei -l "wayback/$WA_JS_ALIVE" -tags token,tokens -es unknown -rl 1000 -c 100 -o "nuclei/$NUCLEI_WAYBACK_SECRETS" -silent; then
                        wayback_secrets=$(wc -l < "nuclei/$NUCLEI_WAYBACK_SECRETS" 2>/dev/null || echo "0")
                        log "SUCCESS" "Wayback scan completed - found $wayback_secrets potential secrets"
                    fi
                fi
            fi
        fi
    else
        log "WARNING" "Katana wayback analysis failed but continuing..."
    fi
else
    log "INFO" "Step 6/8: Skipping wayback analysis (--skip-wayback flag used)"
fi

# Step 7: Headless Crawl Analysis (NEW)
if [ "$SKIP_HEADLESS" = false ]; then
    log "INFO" "Step 7/8: Running headless crawl analysis with Katana..."
    log "INFO" "This may take longer as it uses a headless browser..."
    
    if katana -u "$ALIVE_HTTP" -em js,json -headless -o "headless/$HEADLESS_CRAWL" -silent; then
        headless_count=$(wc -l < "headless/$HEADLESS_CRAWL" 2>/dev/null || echo "0")
        log "SUCCESS" "Found $headless_count URLs via headless crawling"
        
        if [ "$headless_count" -gt 0 ]; then
            log "INFO" "Scanning headless crawl results with Nuclei..."
            if nuclei -l "headless/$HEADLESS_CRAWL" -tags token,tokens -es unknown -rl 1000 -c 100 -o "nuclei/$NUCLEI_HEADLESS_SECRETS" -silent; then
                headless_secrets=$(wc -l < "nuclei/$NUCLEI_HEADLESS_SECRETS" 2>/dev/null || echo "0")
                log "SUCCESS" "Headless crawl scan completed - found $headless_secrets potential secrets"
            else
                log "WARNING" "Nuclei headless scan had issues but continuing..."
            fi
        else
            log "WARNING" "No URLs found during headless crawling"
        fi
    else
        log "WARNING" "Katana headless crawl failed but continuing..."
    fi
else
    log "INFO" "Step 7/8: Skipping headless crawl analysis (--skip-headless flag used)"
fi

# Step 8: Trufflehog Deep Scan
log "INFO" "Step 8/8: Running Trufflehog on combined JS sources..."
rm -rf "$RESPONSES_DIR"

# Combine all JS sources including headless results
combined_js_count=0
js_sources=()

if [ -f "js/$JS_FILES" ]; then
    js_sources+=("js/$JS_FILES")
fi

if [ -f "wayback/$WA_JS_ALIVE" ]; then
    js_sources+=("wayback/$WA_JS_ALIVE")
fi

if [ -f "headless/$HEADLESS_CRAWL" ]; then
    js_sources+=("headless/$HEADLESS_CRAWL")
fi

if [ ${#js_sources[@]} -gt 0 ]; then
    cat "${js_sources[@]}" | sort -u > "$JS_ALL"
    combined_js_count=$(wc -l < "$JS_ALL")
    log "SUCCESS" "Combined $combined_js_count unique JS/JSON URLs from all sources"
else
    log "WARNING" "No JavaScript sources found for combination"
fi

if [ "$combined_js_count" -gt 0 ]; then
    log "INFO" "Downloading $combined_js_count JavaScript/JSON files for deep analysis..."
    if httpx -l "$JS_ALL" -sr -srd "$RESPONSES_DIR" -silent; then
        log "SUCCESS" "JavaScript/JSON files downloaded"
        
        log "INFO" "Running Trufflehog filesystem scan..."
        if trufflehog filesystem "$RESPONSES_DIR" --json > "$TRUFFLEHOG_RESULTS" 2>/dev/null; then
            trufflehog_count=$(wc -l < "$TRUFFLEHOG_RESULTS" 2>/dev/null || echo "0")
            log "SUCCESS" "Trufflehog scan completed - found $trufflehog_count potential secrets"
        else
            log "WARNING" "Trufflehog scan completed with warnings"
        fi
    else
        log "WARNING" "Some JavaScript/JSON files could not be downloaded"
    fi
else
    log "WARNING" "No JavaScript/JSON files found for Trufflehog analysis"
fi

# Generate summary report
log "SUCCESS" "Scan completed! Generating summary report..."

echo ""
echo "=================================="
echo "    SECRETS SCAN SUMMARY REPORT"
echo "=================================="
echo ""

# Count results safely
host_secrets=$(wc -l < "nuclei/$NUCLEI_HOSTS_SECRETS" 2>/dev/null || echo "0")
js_secrets=$(wc -l < "nuclei/$NUCLEI_JS_SECRETS" 2>/dev/null || echo "0")
wayback_secrets=$(wc -l < "nuclei/$NUCLEI_WAYBACK_SECRETS" 2>/dev/null || echo "0")
headless_secrets=$(wc -l < "nuclei/$NUCLEI_HEADLESS_SECRETS" 2>/dev/null || echo "0")
trufflehog_count=$(wc -l < "$TRUFFLEHOG_RESULTS" 2>/dev/null || echo "0")

echo "📊 Scan Statistics:"
echo "  • Subdomains discovered: $(wc -l < "$SUBS" 2>/dev/null || echo "0")"
echo "  • Open ports found: $(wc -l < "$NAABU_OUT" 2>/dev/null || echo "0")"
echo "  • Live HTTP services: $(wc -l < "$ALIVE_HTTP" 2>/dev/null || echo "0")"
echo "  • JavaScript files collected: $(wc -l < "js/$JS_FILES" 2>/dev/null || echo "0")"
if [ "$SKIP_WAYBACK" = false ]; then
    echo "  • Wayback JS files found: $(wc -l < "wayback/$WA_JS_ALIVE" 2>/dev/null || echo "0")"
fi
if [ "$SKIP_HEADLESS" = false ]; then
    echo "  • Headless crawl URLs found: $(wc -l < "headless/$HEADLESS_CRAWL" 2>/dev/null || echo "0")"
fi
echo ""

echo "🔍 Secrets Discovery Results:"
echo "  • Host-based secrets: $host_secrets (nuclei/$NUCLEI_HOSTS_SECRETS)"
echo "  • JavaScript secrets: $js_secrets (nuclei/$NUCLEI_JS_SECRETS)"
if [ "$SKIP_WAYBACK" = false ]; then
    echo "  • Wayback secrets: $wayback_secrets (nuclei/$NUCLEI_WAYBACK_SECRETS)"
fi
if [ "$SKIP_HEADLESS" = false ]; then
    echo "  • Headless crawl secrets: $headless_secrets (nuclei/$NUCLEI_HEADLESS_SECRETS)"
fi
echo "  • Trufflehog findings: $trufflehog_count ($TRUFFLEHOG_RESULTS)"
echo ""

total_secrets=$((host_secrets + js_secrets + wayback_secrets + headless_secrets + trufflehog_count))
echo "🎯 Total potential secrets found: $total_secrets"
echo ""

echo "📁 Output files location: $(pwd)"
echo "📝 Detailed log: $LOG_FILE"
echo ""

if [ "$total_secrets" -gt 0 ]; then
    echo "⚠️  Remember to:"
    echo "  • Validate all findings manually"
    echo "  • Check for false positives"
    echo "  • Handle sensitive data responsibly"
    echo "  • Follow responsible disclosure practices"
fi

echo ""
echo "🔧 Scan Methods Used:"
echo "  • Static JS collection: ✓"
if [ "$SKIP_WAYBACK" = false ]; then
    echo "  • Wayback Machine: ✓"
else
    echo "  • Wayback Machine: ⏭️ (skipped)"
fi
if [ "$SKIP_HEADLESS" = false ]; then
    echo "  • Headless crawling: ✓"
else
    echo "  • Headless crawling: ⏭️ (skipped)"
fi
echo "  • Deep content analysis: ✓"

log "SUCCESS" "Pipeline completed successfully with $total_secrets total findings"
