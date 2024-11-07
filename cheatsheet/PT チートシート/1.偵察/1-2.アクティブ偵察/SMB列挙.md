## Linux
```sh

smbclient -L //SERVER_IP/

# guestユーザが有効になってるか確認
smbclient -L //SERVER_IP/ -U 'guest'
smbclient -L //192.168.231.63 -p 4455 -U hr_admin --password=Welcome1234

sudo nbtscan -r 192.168.50.0/24

enum4linux -a 192.168.50.150
enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>
enum4linux-ng -A 192.168.50.150

nmap -v -p 139,445 --script smb-os-discovery 192.168.50.150

crackmapexec smb 10.10.10.10 --users [-u <username> -p <password> -H <HASH>]
crackmapexec smb 10.10.10.10 --groups [-u <username> -p <password> -H <HASH>]
crackmapexec smb 10.10.10.10 --groups --loggedon-users [-u <username> -p <password> -H <HASH>]

```


## Windows
```sh
net view \\IP /all
```