I'll break down this bug bounty hunting methodology step-by-step with detailed explanations of how each tool works and what's happening behind the scenes.

---

## **Complete Bug Bounty Methodology Breakdown**

### **Step 1: Reconnaissance with Shodan**

**What is Shodan?**
Shodan is a search engine for internet-connected devices. Unlike Google (which indexes web content), Shodan scans the internet and indexes **banners** - the metadata that servers send when you connect to them.

**How to set it up:**
```bash
# Install Shodan CLI
pip install shodan

# Initialize with your API key (get from shodan.io after signing up)
shodan init YOUR_API_KEY_HERE
```

**Running a search:**
```bash
shodan search --fields ip_str,port,org,http.title 'org:"Target Org" http.title:"Admin"' --limit 1000 > shodan_results.csv
```

**What each part means:**
- `--fields ip_str,port,org,http.title` - Only extract these columns (IP address, port number, organization name, webpage title)
- `'org:"Target Org"'` - Filter for assets belonging to the target company
- `http.title:"Admin"` - Look for pages with "Admin" in the title (potential admin panels)
- `--limit 1000` - Get maximum 1000 results
- `> shodan_results.csv` - Save output to CSV file

**What you get:**
A CSV file like this:
```
192.168.1.100,443,Target Org,Admin Login Portal
203.0.113.50,8080,Target Org,Admin Dashboard
```

---

### **Step 2: Extract and Clean Target List**

**Goal:** Get a clean list of just IP addresses for the next steps.

```bash
cut -d',' -f1 shodan_results.csv | sort -u > targets_ips.txt
```

**Breaking it down:**
- `cut -d',' -f1` - Cut the CSV using comma delimiter, take field 1 (IP address)
- `sort -u` - Sort and remove duplicates
- `> targets_ips.txt` - Save to file

**Result:** A clean list:
```
192.168.1.100
203.0.113.50
10.0.0.25
```

---

### **Step 3: Check Which Hosts Are Actually Alive (HTTP Probing)**

**Why this matters:** Not all IPs from Shodan will still be online or accessible. This step verifies which ones respond to HTTP/HTTPS.

**Install httpx:**
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**Run the probe:**
```bash
httpx -l targets_ips.txt -o alive.txt
```

**What httpx does:**
1. Takes each IP from `targets_ips.txt`
2. Tries HTTP (port 80) and HTTPS (port 443)
3. Follows redirects
4. Checks if the server responds with a valid HTTP response
5. Outputs full URLs (e.g., `https://192.168.1.100`)

**Example output in alive.txt:**
```
https://192.168.1.100
http://203.0.113.50:8080
https://10.0.0.25
```

**Additional useful httpx options:**
```bash
# Get more info: status codes, titles, tech stack
httpx -l targets_ips.txt -status-code -title -tech-detect -o alive_detailed.txt

# Probe specific ports
httpx -l targets_ips.txt -ports 80,443,8080,8443 -o alive.txt
```

---

### **Step 4: Expand Attack Surface (URL Discovery)**

**Goal:** Find all known endpoints/paths for each domain, not just the homepage.

**Why this matters:** A domain might have `/admin`, `/api/v1/users`, `/backup.zip` etc. These hidden endpoints often have vulnerabilities.

**Install gau (Get All URLs):**
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

**Run URL gathering:**
```bash
gau -b -o gau_urls.txt -i alive.txt
sort -u gau_urls.txt > urls.txt
```

**What gau does:**
- `-b` - Include URLs from common sources (Wayback Machine, Common Crawl, etc.)
- `-i alive.txt` - Read input domains from file
- `-o gau_urls.txt` - Output to file

**Where gau finds URLs:**
1. **Wayback Machine** - Historical snapshots of websites
2. **Common Crawl** - Large web crawl dataset
3. **AlienVault OTX** - Threat intelligence data
4. **URLScan.io** - Web scanning service

**Example output:**
```
https://example.com/
https://example.com/login
https://example.com/admin/dashboard
https://example.com/api/v1/users?id=123
https://example.com/old_backup.zip
```

**Alternative tools:**
```bash
# waybackurls (simpler, just Wayback Machine)
go install github.com/tomnomnom/waybackurls@latest
cat alive.txt | waybackurls > urls.txt

# hakrawler (crawls live sites)
go install github.com/hakluke/hakrawler@latest
cat alive.txt | hakrawler -depth 3 > urls.txt
```

---

### **Step 5: Automated Vulnerability Scanning with Nuclei**

**What is Nuclei?**
Nuclei is a template-based vulnerability scanner. It has thousands of pre-written "templates" that check for:
- Known CVEs (security vulnerabilities)
- Misconfigurations
- Default credentials
- Exposed panels
- Security header issues

**Install Nuclei:**
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Download/update templates
nuclei -update-templates
```

**Run the scan:**
```bash
nuclei -l urls.txt -o nuclei_results.txt
```

**What happens:**
1. Nuclei loads 8000+ templates
2. For each URL in `urls.txt`, it:
   - Sends HTTP requests with payloads
   - Checks responses against template conditions
   - Reports matches

**Example scan with specific severity:**
```bash
# Only high/critical severity
nuclei -l urls.txt -severity high,critical -o critical_vulns.txt

# Specific vulnerability types
nuclei -l urls.txt -tags cve,xss,sqli -o focused_scan.txt

# Specific templates
nuclei -l urls.txt -t nuclei-templates/http/cves/ -o cve_results.txt
```

**Understanding Nuclei output:**
```
[CVE-2021-41773] [http] [critical] https://example.com/cgi-bin/.%2e/.%2e/.%2e/etc/passwd
[apache-detect] [http] [info] https://example.com [Apache/2.4.49]
[exposed-panel] [http] [medium] https://example.com/admin/
```

Format: `[template-name] [protocol] [severity] [URL] [additional-info]`

---

### **Step 6: Pattern Matching for Specific Vulnerability Classes**

**What is GF (Grep Patterns)?**
GF filters URLs based on patterns that indicate potential vulnerabilities.

**Install GF:**
```bash
go install github.com/tomnomnom/gf@latest

# Download common patterns
mkdir ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
```

**Using GF:**
```bash
# Find URLs that might be vulnerable to XSS
cat urls.txt | gf xss > xss_candidates.txt

# Find potential SQL injection points
cat urls.txt | gf sqli > sqli_candidates.txt

# Find potential open redirects
cat urls.txt | gf redirect > redirect_candidates.txt

# Find potential LFI (Local File Inclusion)
cat urls.txt | gf lfi > lfi_candidates.txt
```

**What GF looks for (XSS example):**
URLs with parameters that reflect input:
```
https://example.com/search?q=test
https://example.com/page?name=user
https://example.com/error?msg=invalid
```

---

### **Step 7: Focused XSS Testing with Dalfox**

**What is Dalfox?**
A specialized XSS (Cross-Site Scripting) scanner that tests reflection points.

**Install Dalfox:**
```bash
go install github.com/hahwul/dalfox/v2@latest
```

**Run XSS testing:**
```bash
# Test all XSS candidates
dalfox file xss_candidates.txt -o dalfox_xss_out.txt

# Deeper scan with more payloads
dalfox file xss_candidates.txt --deep-domxss --mining-dom -o results.txt
```

**What Dalfox does:**
1. Takes URLs with parameters
2. Injects XSS payloads like:
   - `<script>alert(1)</script>`
   - `"><img src=x onerror=alert(1)>`
   - DOM-based payloads
3. Checks if payload executes in response
4. Reports confirmed XSS vulnerabilities

**Example output:**
```
[POC][R][BUILT-IN/tomnomnom/1] https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
[POC][V][GET] https://example.com/page?name=%22%3E%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E
```

---

### **Step 8: Service/Port Verification with Nmap (When Needed)**

**When to use Nmap:**
- When you need to confirm what service is running on a port
- To get version information
- To check for additional open ports

**Basic service detection:**
```bash
# Scan common ports with version detection
nmap -sV -p 1-1000 --min-rate 1000 192.168.1.100 -oN nmap_results.txt
```

**Breaking it down:**
- `-sV` - Service version detection
- `-p 1-1000` - Scan ports 1-1000
- `--min-rate 1000` - Send at least 1000 packets/second (faster)
- `-oN` - Output to normal format file

**Example output:**
```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.49
443/tcp  open  ssl/http Apache httpd 2.4.49
```

---

### **Step 9: Automated Pipeline Script**

Here's the complete automation script with explanations:

```bash
#!/usr/bin/env bash
# Save as: bug_bounty_pipeline.sh

# Configuration
TARGET_QUERY='org:"Target Org" http.title:"Admin"'
OUTDIR="./recon_$(date +%Y%m%d_%H%M%S)"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTDIR"
echo -e "${GREEN}[+] Output directory: $OUTDIR${NC}"

# Step 1: Shodan reconnaissance
echo -e "${YELLOW}[*] Step 1: Searching Shodan...${NC}"
shodan search --fields ip_str,port,org,http.title "$TARGET_QUERY" --limit 1000 > "$OUTDIR/shodan_results.csv"
echo -e "${GREEN}[+] Found $(wc -l < "$OUTDIR/shodan_results.csv") results${NC}"

# Step 2: Extract IPs
echo -e "${YELLOW}[*] Step 2: Extracting IPs...${NC}"
cut -d',' -f1 "$OUTDIR/shodan_results.csv" | sort -u > "$OUTDIR/targets_ips.txt"
echo -e "${GREEN}[+] Unique IPs: $(wc -l < "$OUTDIR/targets_ips.txt")${NC}"

# Step 3: Probe for live HTTP services
echo -e "${YELLOW}[*] Step 3: Probing for live HTTP services...${NC}"
httpx -l "$OUTDIR/targets_ips.txt" -status-code -title -tech-detect -o "$OUTDIR/alive.txt"
echo -e "${GREEN}[+] Live hosts: $(wc -l < "$OUTDIR/alive.txt")${NC}"

# Step 4: Gather URLs from multiple sources
echo -e "${YELLOW}[*] Step 4: Gathering URLs...${NC}"
gau --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf --providers wayback,commoncrawl,otx,urlscan \
    -o "$OUTDIR/gau_urls.txt" < "$OUTDIR/alive.txt"
sort -u "$OUTDIR/gau_urls.txt" > "$OUTDIR/urls.txt"
echo -e "${GREEN}[+] Total URLs: $(wc -l < "$OUTDIR/urls.txt")${NC}"

# Step 5: Run Nuclei scan
echo -e "${YELLOW}[*] Step 5: Running Nuclei scan...${NC}"
nuclei -l "$OUTDIR/urls.txt" \
       -t "$NUCLEI_TEMPLATES" \
       -severity critical,high,medium \
       -o "$OUTDIR/nuclei_results.txt" \
       -stats

# Step 6: Pattern matching for specific vulns
echo -e "${YELLOW}[*] Step 6: Pattern matching...${NC}"
cat "$OUTDIR/urls.txt" | gf xss > "$OUTDIR/xss_candidates.txt" 2>/dev/null || true
cat "$OUTDIR/urls.txt" | gf sqli > "$OUTDIR/sqli_candidates.txt" 2>/dev/null || true
cat "$OUTDIR/urls.txt" | gf redirect > "$OUTDIR/redirect_candidates.txt" 2>/dev/null || true

echo -e "${GREEN}[+] XSS candidates: $(wc -l < "$OUTDIR/xss_candidates.txt")${NC}"
echo -e "${GREEN}[+] SQLi candidates: $(wc -l < "$OUTDIR/sqli_candidates.txt")${NC}"

# Step 7: Focused XSS testing (if candidates found)
if [ -s "$OUTDIR/xss_candidates.txt" ]; then
    echo -e "${YELLOW}[*] Step 7: Testing XSS candidates...${NC}"
    dalfox file "$OUTDIR/xss_candidates.txt" -o "$OUTDIR/dalfox_results.txt"
fi

# Summary
echo -e "${GREEN}[+] Scan complete! Results in: $OUTDIR${NC}"
echo -e "${YELLOW}Summary:${NC}"
echo "- Shodan results: $OUTDIR/shodan_results.csv"
echo "- Live hosts: $OUTDIR/alive.txt"
echo "- All URLs: $OUTDIR/urls.txt"
echo "- Nuclei findings: $OUTDIR/nuclei_results.txt"
echo "- XSS candidates: $OUTDIR/xss_candidates.txt"
echo "- Dalfox results: $OUTDIR/dalfox_results.txt"
```

**Run it:**
```bash
chmod +x bug_bounty_pipeline.sh
./bug_bounty_pipeline.sh
```

---

### **Step 10: Manual Triage and Verification**

**This is the MOST IMPORTANT step** - automation finds candidates, but you must manually verify.

**Triage process:**

1. **Read Nuclei results:**
```bash
# Filter by severity
grep "\[critical\]" nuclei_results.txt
grep "\[high\]" nuclei_results.txt
```

2. **Open promising findings in browser:**
   - Check if the vulnerability is real
   - Verify it's actually exploitable
   - Check if it's in-scope

3. **Create minimal PoC:**
```
# Bad PoC:
"I ran a scanner and it said there's XSS"

# Good PoC:
URL: https://example.com/search?q=test
Payload: https://example.com/search?q=<script>alert(document.domain)</script>
Evidence: [Screenshot showing alert box with "example.com"]
Impact: Attacker can steal session cookies and perform actions as victim
```

4. **Use Burp Suite for deeper testing:**
   - Intercept requests
   - Modify parameters
   - Test edge cases
   - Validate findings

---

## **Tool Summary Table**

| Tool | Purpose | What it finds |
|------|---------|---------------|
| **Shodan** | Internet-wide reconnaissance | Exposed services, IPs, technologies |
| **httpx** | HTTP probing | Live web services, status codes, titles |
| **gau** | URL discovery | Historical URLs, hidden endpoints |
| **Nuclei** | Vulnerability scanning | CVEs, misconfigurations, exposed panels |
| **GF** | Pattern matching | URLs likely vulnerable to XSS, SQLi, etc. |
| **Dalfox** | XSS testing | Confirmed XSS vulnerabilities |
| **Nmap** | Port/service scanning | Open ports, service versions |

---

## **Critical Warnings**

⚠️ **Only scan authorized targets:**
- Bug bounty programs with published scope
- Your own systems
- Systems you have written permission to test

⚠️ **Read the program rules:**
- Some disallow automated scanning
- Some have specific out-of-scope items
- Some limit rate of requests

⚠️ **Be responsible:**
- Don't cause DoS (Denial of Service)
- Don't access/modify user data
- Report vulnerabilities properly

---

Would you like me to:
1. Create a more detailed example for a specific step?
2. Show you how to set up these tools in a virtual environment?
3. Explain how to report findings professionally to bug bounty programs?
