より詳しい情報は[wiki](https://sliver.sh/)を参照

### サーバ側
```sh
# サーバ起動
sudo /root/sliver-server
# .------..------..------..------..------..------.
# |S.--. ||L.--. ||I.--. ||V.--. ||E.--. ||R.--. |
# | :/\: || :/\: || (\/) || :(): || (\/) || :(): |
# | :\/: || (__) || :\/: || ()() || :\/: || ()() |
# | '--'S|| '--'L|| '--'I|| '--'V|| '--'E|| '--'R|
# `------'`------'`------'`------'`------'`------'
#
# All hackers gain epic
# [*] Server v1.5.42 - 85b0e870d05ec47184958dbcb871ddee2eb9e3df
# [*] Welcome to the sliver shell, please type 'help' for options
# 
# [*] Check for updates with the 'update' command

[server] sliver >  multiplayer
# [*] Multiplayer mode enabled!
```

```sh
# ユーザ作成
new-operator lhost C2-SERVER-IP -n USERNAME -s /save/config.cfg
# Saved /save/path.cfg
```

### クライアント側
```sh
# ユーザ追加
sliver import /save/config.cfg

# クライアント起動
sliver
# ? Select a server:  [Use arrows to move, enter to select, type to filter]
#   root@localhost (a69f9df63633cf6b)
# > sliver-user@127.0.0.1 (634c37f944fcc0f3)
#
#
#           ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
#      	▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
#   	░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
#   	  ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
#   	▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
#   	▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
#   	░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
#   	░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
#   		  ░      ░  ░ ░        ░     ░  ░   ░
# 
# All hackers gain haste
# [*] Server v1.5.42 - 85b0e870d05ec47184958dbcb871ddee2eb9e3df
# [*] Welcome to the sliver shell, please type 'help' for options
# 
# [*] Check for updates with the 'update' command
```

```sh
# Listener起動
sliver > mtls -l 1234
# [*] Starting mTLS listener ...
#
# [*] Successfully started job #1
# 
sliver > jobs
#
#  ID   Name   Protocol   Port    Stage Profile 
# ==== ====== ========== ======= ===============
#  1    mtls   tcp        1234                  
```
エージェント作成コマンドは[[PT チートシート/2.資源開発/ペイロード作成/Sliver C2|こちら]]