```sh
# 使用条件
# ユーザがリモートホストでAdministratorsに属してること
# ADMINS$がsmbで共有されていること
# ファイルとプリンタの共有がオンになっていること
./PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```