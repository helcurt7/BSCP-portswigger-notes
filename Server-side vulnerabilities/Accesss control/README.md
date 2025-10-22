# Access Control


<span style="font-size:1.15em"><strong>/admin /robots.txt view page source login admin=true   admin post id=administrator  intercept ...can see password</strong></span>

<h2 style="font-size:1.6em">Unprotected admin functionality</h2>

after tried <span style="font-size:1.15em"><strong>/admin</strong></span> <span style="font-size:1.15em"><strong>/administrator</strong></span> does not works we look for <span style="font-size:1.15em"><strong>/robots.txt</strong></span>

---

![robots.txt explanation](https://github.com/user-attachments/assets/c53ab4fe-66e8-4598-87e6-a6638c6cf051)

<span style="font-size:1.15em"><strong>robots.txt</strong></span> is a text file that store web crawler use by search engine to disallow or allow to search up to which web directory

after we saw <span style="font-size:1.15em"><strong>Disallow: /administrator-panel</strong></span> we append to the link

---

![administrator panel found](https://github.com/user-attachments/assets/92827a15-753a-4949-9c86-da267f498c64)

then we delete the carlos done

<span style="font-size:1.15em"><strong>[https://insecure-website.com/administrator-panel-yb556](https://insecure-website.com/administrator-panel-yb556)</strong></span>

<h2 style="font-size:1.6em">Unprotected admin functionality — unpredictable URL</h2>

---

![admin-lpq23j found](https://github.com/user-attachments/assets/9aefafe2-cc48-4f75-ae88-b7d5966a90bb)

as u can see like this we found <span style="font-size:1.15em"><strong>/admin-lpq23j</strong></span> then we access by append to the website link and done

<h2 style="font-size:1.6em">User role controlled by request parameter</h2>

basically

1. go to my account login as <span style="font-size:1.15em"><strong>wiener:peter</strong></span>
2. burpsuite inspect u will see <span style="font-size:1.15em"><strong>admin=false</strong></span>
3. keep forwarding and change <span style="font-size:1.15em"><strong>admin=true</strong></span> then delete carlos also change <span style="font-size:1.15em"><strong>admin=true</strong></span> done

<h2 style="font-size:1.6em">Horizontal privilege escalation</h2> able to access other ppl resources such as <span style="font-size:1.15em"><strong>id=1</strong></span> change to <span style="font-size:1.15em"><strong>id=2</strong></span> and access another account

1. first find a blog post post by carlos then u will saw the user <span style="font-size:1.15em"><strong>id=whos guid</strong></span> then go to my account and replace ur id to carlos id u found the api key easy

---

![replace with administrator guid](https://github.com/user-attachments/assets/7bc6f255-4fc3-4d28-9da7-f9c4fb70734c)

i can even replace with administrator guid

---

![change id to administrator](https://github.com/user-attachments/assets/0f1d9dfb-74af-4360-b925-8a225516fafa)

<h2 style="font-size:1.6em">Horizontal to vertical privilege escalation</h2>

1. first i log in to my <span style="font-size:1.15em"><strong>wiener:peter</strong></span> account i saaw <span style="font-size:1.15em"><strong>id=wiener</strong></span> so i change <span style="font-size:1.15em"><strong>id=administrator</strong></span> i got into administrator account

press <span style="font-size:1.15em"><strong>update the password</strong></span> with burpsuite interception and we can see the password is <span style="font-size:1.15em"><strong>iev7k0li8m58h1vujo8c</strong></span>

---

![password captured](https://github.com/user-attachments/assets/93f117ed-6473-4dee-b1b2-b35973b8238d)

![admin login screenshot](https://github.com/user-attachments/assets/b7a7fa65-eea5-40bb-827a-664cc6a203a4)

then we log in administrator with the password and delete carlos done

---

*just add github markdown dont change anything*
