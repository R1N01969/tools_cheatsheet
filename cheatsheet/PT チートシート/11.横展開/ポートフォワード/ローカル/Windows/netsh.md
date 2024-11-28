```sh
# 実行には管理者権限が必要
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

C:\Windows\system32>netstat -anp TCP | find "2222"
#   TCP    192.168.50.64:2222     0.0.0.0:0              LISTENING

C:\Windows\system32>netsh interface portproxy show all
# 
# Listen on ipv4:             Connect to ipv4:
# 
# Address         Port        Address         Port
# --------------- ----------  --------------- ----------
# 192.168.50.64   2222        10.4.50.215     22
```

```sh
# ファイアウォールルールの追加
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow

# ファイアウォールルールの削除
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
# ポートフォワード設定の削除
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```