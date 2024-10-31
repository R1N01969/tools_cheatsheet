### リモートから実行
```sh
bloodhound-python -u USER -p PASS -ns DC-IP -d DOMAIN -c All --zip
bloodhound-python -u USER --hashes HASH -ns DC-IP -d DOMAIN -c All --zip
```

### 侵入ホスト上で実行
```sh
.\SharpHound.exe --CollectionMethod All --LdapUsername USER --LdapPassword PASS --domain DOMAIN --domaincontroller DC-IP --OutputDirectory PATH
```