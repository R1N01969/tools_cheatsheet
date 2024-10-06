## Linux
```sh

smbclient -L //SERVER_IP/

# guestユーザが有効になってるか確認
smbclient -L //SERVER_IP/ -U 'guest'

sudo nbtscan -r 192.168.50.0/24

enum4linux -a 192.168.50.150
enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>
enum4linux-ng -A 192.168.50.150

nmap -v -p 139,445 --script smb-os-discovery 192.168.50.150
```


## Windows
```sh
net view \\IP /all
```