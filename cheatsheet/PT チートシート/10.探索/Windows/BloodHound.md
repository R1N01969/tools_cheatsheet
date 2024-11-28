### リモートから実行
```sh
bloodhound-python -u USER -p PASS -ns DC-IP -d DOMAIN -c All --zip
bloodhound-python -u USER --hashes HASH -ns DC-IP -d DOMAIN -c All --zip
```

### 侵入ホスト上で実行
```sh
.\SharpHound.exe --CollectionMethods All --LdapUsername USER --LdapPassword PASS --domain DOMAIN --domaincontroller DC-IP --OutputDirectory PATH
```

```sh
Import-Module .\SharpHound.ps1

Get-Help Invoke-BloodHound

Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```

- HasSession: セッションを持ってるホストにユーザの資格情報がキャッシュされている可能性がある