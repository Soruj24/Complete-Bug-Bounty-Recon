#!/bin/bash

# Professional Bug Bounty Reconnaissance & Vulnerability Scanner (Amass-Free)
# Author: Security Researcher
# Version: 2.2
# Last Modified: $(date +%Y-%m-%d)

# === Configuration ===
if [ -z "$1" ]; then
    echo "Usage: $0 <domain> [--aggressive]"
    echo "Options:"
    echo "  --aggressive  Enable intrusive checks (use with caution)"
    exit 1
fi

# Initialize variables
DOMAIN=$1
AGGRESSIVE_MODE=false
[[ "$2" == "--aggressive" ]] && AGGRESSIVE_MODE=true

OUTPUT_DIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${OUTPUT_DIR}/logs" "${OUTPUT_DIR}/scans" "${OUTPUT_DIR}/exports"

# Rate limiting configuration
RATE_LIMIT="75"
THREADS=20
TIMEOUT=10

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "${OUTPUT_DIR}/logs/execution.log"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Dependency check (Amass removed)
check_dependencies() {
    declare -a TOOLS=("subfinder" "assetfinder" "httpx" "waybackurls" "gau" "katana" "paramspider" "nuclei" "ffuf" "jq")
    for tool in "${TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error_exit "Missing dependency: $tool"
        fi
    done
}

# Cleanup function
cleanup() {
    log "Cleaning temporary files..."
    find "${OUTPUT_DIR}" -type f -name "*.tmp" -delete
}

# Main execution
main() {
    log "Starting reconnaissance on: ${DOMAIN}"
    check_dependencies
    trap cleanup EXIT

    # === Phase 1: Subdomain Enumeration ===
    log "Phase 1/8: Subdomain Discovery"
    {
        log "Running subfinder..."
        subfinder -d "${DOMAIN}" -silent -o "${OUTPUT_DIR}/scans/subfinder.tmp"
        
        log "Running assetfinder..."
        assetfinder --subs-only "${DOMAIN}" > "${OUTPUT_DIR}/scans/assetfinder.tmp"
        
        log "Querying crt.sh..."
        curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' > "${OUTPUT_DIR}/scans/crtsh.tmp"
    } 2>> "${OUTPUT_DIR}/logs/subdomains.log"

    # Merge and deduplicate
    cat "${OUTPUT_DIR}"/scans/*.tmp | sort -u > "${OUTPUT_DIR}/scans/all_subdomains.txt"
    log "Found $(wc -l < "${OUTPUT_DIR}/scans/all_subdomains.txt") unique subdomains"

    # === Phase 2: Live Host Verification ===
    log "Phase 2/8: Live Host Detection"
    httpx -l "${OUTPUT_DIR}/scans/all_subdomains.txt" \
        -silent \
        -threads "${THREADS}" \
        -rate-limit "${RATE_LIMIT}" \
        -timeout "${TIMEOUT}" \
        -status-code \
        -title \
        -tech-detect \
        -json \
        -o "${OUTPUT_DIR}/scans/live_hosts.json" \
        2>> "${OUTPUT_DIR}/logs/httpx.log"

    jq -r '.url' "${OUTPUT_DIR}/scans/live_hosts.json" > "${OUTPUT_DIR}/scans/live_hosts.txt"
    log "Identified $(wc -l < "${OUTPUT_DIR}/scans/live_hosts.txt") live hosts"

    # === Phase 3: URL Collection ===
    log "Phase 3/8: Historical URL Collection"
    {
        log "Querying Wayback Machine..."
        waybackurls < "${OUTPUT_DIR}/scans/live_hosts.txt" > "${OUTPUT_DIR}/scans/wayback.tmp"
        
        log "Running GAU..."
        gau --subs "${DOMAIN}" > "${OUTPUT_DIR}/scans/gau.tmp"
        
        log "Running Katana..."
        katana -list "${OUTPUT_DIR}/scans/live_hosts.txt" -jc -kf all -d 3 -silent -o "${OUTPUT_DIR}/scans/katana.tmp"
    } 2>> "${OUTPUT_DIR}/logs/urls.log"

    sort -u "${OUTPUT_DIR}"/scans/*.tmp > "${OUTPUT_DIR}/scans/all_urls.txt"
    log "Collected $(wc -l < "${OUTPUT_DIR}/scans/all_urls.txt") unique URLs"

    # === Phase 4: Parameter Extraction ===
    log "Phase 4/8: Parameter Discovery"
    {
        log "Running ParamSpider..."
        paramspider -d "${DOMAIN}" -o "${OUTPUT_DIR}/scans/paramspider.tmp"
        
        log "Extracting parameters..."
        grep "=" "${OUTPUT_DIR}/scans/all_urls.txt" | unfurl -u keys > "${OUTPUT_DIR}/scans/params.tmp"
        grep "=" "${OUTPUT_DIR}/scans/all_urls.txt" | unfurl -u keypairs >> "${OUTPUT_DIR}/scans/params.tmp"
    } 2>> "${OUTPUT_DIR}/logs/parameters.log"

    sort -u "${OUTPUT_DIR}/scans/params.tmp" > "${OUTPUT_DIR}/scans/parameterized_urls.txt"
    log "Extracted $(wc -l < "${OUTPUT_DIR}/scans/parameterized_urls.txt") parameterized URLs"

    # === Phase 5: Vulnerability Scanning ===
    log "Phase 5/8: Automated Vulnerability Scanning"
    
    # IDOR Detection
    log "Scanning for IDOR vulnerabilities..."
    grep -Ei 'id=|user=|account=|uid=|profile=|order=|number=|customer=|client=' "${OUTPUT_DIR}/scans/parameterized_urls.txt" > "${OUTPUT_DIR}/scans/idor_candidates.txt"
    grep -Ei 'ssn=|credit=|score=|report=|birth=|dob=|address=' "${OUTPUT_DIR}/scans/parameterized_urls.txt" >> "${OUTPUT_DIR}/scans/idor_candidates.txt"

    # Nuclei Scans
    log "Running comprehensive Nuclei scans..."
    declare -a NUCLEI_TEMPLATES=(
        "~/nuclei-templates/sql-injection/"
        "~/nuclei-templates/xss/"
        "~/nuclei-templates/api/"
        "~/nuclei-templates/ssrf/"
        "~/nuclei-templates/authentication/"
    )
    
    for template in "${NUCLEI_TEMPLATES[@]}"; do
        nuclei -l "${OUTPUT_DIR}/scans/live_hosts.txt" \
            -t "${template}" \
            -rate-limit "${RATE_LIMIT}" \
            -o "${OUTPUT_DIR}/scans/nuclei_results.txt" \
            -silent \
            2>> "${OUTPUT_DIR}/logs/nuclei.log"
    done

    # === Phase 6: Content Discovery ===
    log "Phase 6/8: Directory Bruteforcing"
    mkdir -p "${OUTPUT_DIR}/ffuf"
    
    while read -r url; do
        domain_clean=$(echo "${url}" | sed 's~https\?://~~g' | tr "/" "_")
        
        log "Scanning ${url} with FFUF..."
        ffuf -u "${url}/FUZZ" \
            -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt \
            -t "${THREADS}" \
            -rate-limit "${RATE_LIMIT}" \
            -timeout "${TIMEOUT}" \
            -o "${OUTPUT_DIR}/ffuf/${domain_clean}.json" \
            -of json \
            -s \
            2>> "${OUTPUT_DIR}/logs/ffuf.log"
    done < "${OUTPUT_DIR}/scans/live_hosts.txt"

    # === Phase 7: Technology Analysis ===
    log "Phase 7/8: Technology Stack Analysis"
    jq -r '.tech_detect | select(. != null) | [.url, .tech] | @tsv' "${OUTPUT_DIR}/scans/live_hosts.json" > "${OUTPUT_DIR}/exports/technology_stack.tsv"

    # === Phase 8: Reporting ===
    log "Phase 8/8: Report Generation"
    {
        echo "# Comprehensive Reconnaissance Report"
        echo "## Target: ${DOMAIN}"
        echo "## Date: $(date)"
        echo ""
        echo "## Key Statistics"
        echo "- Subdomains Discovered: $(wc -l < "${OUTPUT_DIR}/scans/all_subdomains.txt")"
        echo "- Live Hosts Identified: $(wc -l < "${OUTPUT_DIR}/scans/live_hosts.txt")"
        echo "- Unique URLs Collected: $(wc -l < "${OUTPUT_DIR}/scans/all_urls.txt")"
        echo "- Parameterized Endpoints: $(wc -l < "${OUTPUT_DIR}/scans/parameterized_urls.txt")"
        echo ""
        echo "## Critical Findings"
        echo "- IDOR Candidates: $(wc -l < "${OUTPUT_DIR}/scans/idor_candidates.txt")"
        echo "- SQL Injection Findings: $(grep -c "sql-injection" "${OUTPUT_DIR}/scans/nuclei_results.txt")"
        echo "- XSS Vulnerabilities: $(grep -c "xss" "${OUTPUT_DIR}/scans/nuclei_results.txt")"
        echo "- API Security Issues: $(grep -c "api" "${OUTPUT_DIR}/scans/nuclei_results.txt")"
        echo ""
        echo "## Recommended Actions"
        echo "1. Prioritize manual verification of high-risk findings"
        echo "2. Conduct authenticated testing on identified endpoints"
        echo "3. Perform business logic testing on payment/order flows"
        echo ""
        echo "Full results available in: ${OUTPUT_DIR}"
    } > "${OUTPUT_DIR}/report.md"

    # Generate CSV exports
    echo "url,status_code,title,technologies" > "${OUTPUT_DIR}/exports/live_hosts.csv"
    jq -r '[.url, .status_code, .title, .tech_detect? // ""] | @csv' "${OUTPUT_DIR}/scans/live_hosts.json" >> "${OUTPUT_DIR}/exports/live_hosts.csv"

    log "Reconnaissance complete. Results saved to: ${OUTPUT_DIR}"
    log "Report generated: ${OUTPUT_DIR}/report.md"
}

main
