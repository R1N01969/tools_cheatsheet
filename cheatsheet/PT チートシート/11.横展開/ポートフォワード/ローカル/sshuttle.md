
sshuttle [1](https://portal.offsec.com/courses/pen-200-44065/learning/port-redirection-and-ssh-tunneling-48849/ssh-tunneling-48917/ssh-remote-dynamic-port-forwarding-48854#fn-local_id_151-1)_は_、SSH トンネルを経由するトラフィックを強制するローカル ルートを設定することで、SSH 接続を VPN のようなものに変えるツールです。ただし、SSH クライアントではルート権限、SSH サーバーでは Python3 が必要なので、必ずしも最も軽量なオプションとは言えません。ただし、適切なシナリオでは非常に便利です。

```sh

# 中継端末から転送先端末にローカルポートフォワード
# ここは中継端末で実行
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22

# sshuttleでVPNっぽくできる, ssh接続先には中継端末を指定
# ここは自端末で実行
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```