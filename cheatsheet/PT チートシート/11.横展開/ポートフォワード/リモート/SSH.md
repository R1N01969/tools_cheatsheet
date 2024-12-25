```sh
# -R: リモートポートフォワード
# 自端末のIP:自端末でバインドするポート:（中継端末からの）転送先のIP:転送先のポート
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```
![[Pasted image 20241221234332.png]]


```sh
# 自端末のリスニングポートのみ指定：ダイナミックリモートポートフォワード
ssh -N -R 9998 kali@192.168.118.4

# ポートフォワードが機能してるか確認
ss -tlnpu
# State                Recv-Q               Send-Q                              Local Address:Port                                Peer Address:Port               Process   
# LISTEN               0                    128                                     127.0.0.1:9998                                     0.0.0.0:* 
```
![[Pasted image 20241221234351.png]]
