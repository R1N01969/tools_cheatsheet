```sh
# 中継端末で実行
# 中継端末の2345ポートへの通信を10.4.231.215:5432へ転送
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.231.215:5432
```