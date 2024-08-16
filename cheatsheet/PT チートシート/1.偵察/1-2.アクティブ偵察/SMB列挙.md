## Linux
```sh

smbclient -L //SERVER_IP/

sudo nbtscan -r 192.168.50.0/24
enum4linux -a 192.168.50.150
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.150
```


## Windows
```sh
net view \\IP /all
```