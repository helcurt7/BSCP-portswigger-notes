# Authentication vulnerabilities

burpsuite sniper username diff length sniper password enter ver code victim log in skip ver code page /my-account


Authentication is the process of verifying that a user is who they claim to be. Authorization involves verifying whether a user is allowed to do something.

## Username enumeration

is when the website show the username exist eg. the username is already taken or incorrect password but correct username

how do we know which username exist we send to intruder using sniper and bruteforce the given username list we found ftp is diff in length most likely can be bruteforce

<img width="1064" height="756" alt="image" src="https://github.com/user-attachments/assets/1d7f5ca3-0c97-4413-97a3-fcc1b954c462" />

then we found ftp password is jennifer since the length is 185

<img width="869" height="782" alt="image" src="https://github.com/user-attachments/assets/c8983018-aa51-4d2c-90e2-efc8e0f28215" />

## Bypassing two-factor authentication

1. first log in to your account and enter verification code

2. log in to victim account and it prompt u to enter verification code

3. append /my-account to directly enter and skip that page
