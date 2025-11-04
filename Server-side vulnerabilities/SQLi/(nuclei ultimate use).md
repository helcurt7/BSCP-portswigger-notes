Here's the **optimized, professional-grade recon command** that works in most scenarios:

## 🚀 Ultimate One-Liner Recon Command

```bash
subfinder -d example.com -silent | httpx -silent -threads 100 | tee live-subdomains.txt | waybackurls | gau | katana -silent -jc -aff | uro | grep -vE "\.(css|js|png|jpg|jpeg|gif|svg|woff|ttf|eot|ico)" | sort -u > all-urls.txt
```

## 🔧 Break Down & Explanation

### **Part 1: Subdomain Discovery**
```bash
subfinder -d example.com -silent | httpx -silent -threads 100
```
- `subfinder`: Fast subdomain enumeration
- `httpx`: Verify which subdomains are live
- `-threads 100`: Faster processing
- `-silent`: Clean output

### **Part 2: URL Discovery (Multiple Sources)**
```bash
| waybackurls | gau | katana -silent -jc -aff
```
- `waybackurls`: Historical URLs from Wayback Machine
- `gau`: GetAllUrls - fetches from multiple sources
- `katana`: Modern crawler with JS rendering
  - `-jc`: JavaScript rendering
  - `-aff`: Automatic form filling

### **Part 3: Filtering & Cleaning**
```bash
| uro | grep -vE "\.(css|js|png|jpg|jpeg|gif|svg|woff|ttf|eot|ico)" | sort -u
```
- `uro`: URL normalization (removes duplicates)
- `grep -vE`: Exclude static files
- `sort -u`: Remove duplicates

## 📊 Complete Professional Recon Script

Save this as `recon.sh`:

```bash
#!/bin/bash

domain=$1
if [ -z "$domain" ]; then
    echo "Usage: ./recon.sh example.com"
    exit 1
fi

echo "[+] Starting recon for: $domain"
mkdir -p recon-$domain
cd recon-$domain

echo "[1] Subdomain discovery..."
subfinder -d $domain -silent | httpx -silent -threads 100 > live-subdomains.txt
echo "    Found: $(cat live-subdomains.txt | wc -l) live subdomains"

echo "[2] URL discovery..."
cat live-subdomains.txt | waybackurls > wayback-urls.txt
cat live-subdomains.txt | gau > gau-urls.txt
cat live-subdomains.txt | katana -silent -jc -aff > katana-urls.txt

echo "[3] Merging and filtering URLs..."
cat wayback-urls.txt gau-urls.txt katana-urls.txt | uro | \
grep -vE "\.(css|js|png|jpg|jpeg|gif|svg|woff|ttf|eot|ico|pdf|zip|tar|gz)" | \
sort -u > all-urls.txt
echo "    Total unique URLs: $(cat all-urls.txt | wc -l)"

echo "[4] Extracting URLs with parameters..."
cat all-urls.txt | grep "=" | grep -v "\.xml" | grep -v "\.json" > urls-with-params.txt
echo "    URLs with parameters: $(cat urls-with-params.txt | wc -l)"

echo "[5] Extracting parameters for manual testing..."
cat urls-with-params.txt | unfurl keys | sort -u > parameters.txt
echo "    Unique parameters: $(cat parameters.txt | wc -l)"

echo "[6] Creating Nuclei target lists..."
# For SQLi testing
cat urls-with-params.txt > nuclei-sqli-targets.txt
# For general scanning
cat all-urls.txt > nuclei-all-targets.txt

echo "[+] Recon complete!"
echo "    - Live subdomains: live-subdomains.txt"
echo "    - All URLs: all-urls.txt"
echo "    - URLs with params: urls-with-params.txt"
echo "    - Parameters: parameters.txt"
echo "    - Nuclei targets: nuclei-*.txt"
```

## 🎯 Usage

```bash
# Make executable
chmod +x recon.sh

# Run recon
./recon.sh osas.com

# Then run Nuclei
nuclei -l recon-osas.com/nuclei-sqli-targets.txt -t sqli/ -o osas-sqli-results.txt
```

## 🔥 Even Better: Advanced One-Liner with Rate Limiting

```bash
subfinder -d example.com -silent | \
httpx -silent -threads 50 | \
tee live.txt | \
parallel -j 10 "echo {} | waybackurls; echo {} | gau; echo {} | katana -silent -jc" 2>/dev/null | \
uro | \
grep -vE "\.(css|js|png|jpg|jpeg|gif|svg|woff|ttf|eot|ico|pdf)" | \
sort -u > urls.txt
```

## 📈 For Massive Scope (Enterprise Level)

```bash
# For very large scopes, add rate limiting
subfinder -d example.com -silent | \
httpx -silent -threads 50 -rate-limit 100 | \
tee live.txt | \
while read domain; do
    echo "$domain" | waybackurls
    echo "$domain" | gau
    echo "$domain" | katana -silent -jc -c 10 -hl -fhr
    sleep 0.5  # Rate limiting
done | \
uro | \
grep -vE "\.(css|js|png|jpg|jpeg|gif|svg|woff|ttf|eot|ico|pdf|zip|tar|gz|mp4|avi|mov)" | \
sort -u > urls.txt
```

## 🛠️ Installation Requirements

Make sure you have these tools installed:

```bash
# Subdomain discovery
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# URL discovery
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# URL processing
go install -v github.com/snovvcrash/uro@latest
go install -v github.com/tomnomnom/unfurl@latest

# Parallel processing (optional)
sudo apt install parallel  # On Ubuntu
```

## 🎯 Final Optimized Command for Most Scenarios

```bash
# This is the sweet spot - fast, comprehensive, and safe
subfinder -d example.com -silent | \
httpx -silent -threads 100 | \
tee live-subdomains.txt | \
shuf | \
head -1000 | \  # Limit to 1000 subdomains to avoid being blocked
parallel -j 5 "echo {} | waybackurls; echo {} | gau" 2>/dev/null | \
katana -silent -jc -c 10 | \
uro | \
grep -vE "\.(css|js|png|jpg|jpeg|gif|svg|woff|ttf|eot|ico)" | \
sort -u | \
tee all-urls.txt
```

## 💡 Pro Tips:

1. **Use `shuf | head -1000`** to randomly sample subdomains and avoid being blocked
2. **Add `-rate-limit`** in httpx for large scopes
3. **Use `parallel -j 5`** to control concurrency
4. **Always exclude static files** to reduce noise
5. **Save intermediate results** with `tee` for debugging

This approach gives you:
- ✅ **Comprehensive coverage** from multiple sources
- ✅ **Fast execution** with parallel processing
- ✅ **Clean results** without noise
- ✅ **Safe scanning** with rate limiting
- ✅ **Ready for Nuclei** with proper target lists

The final output `urls-with-params.txt` is perfect for SQLi testing with Nuclei!
