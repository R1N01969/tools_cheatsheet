```sh
# 指定ドメインのレコードを含むネームサーバの取得
host -t ns DOMAIN_NAME
# offseclab.io name server ns-1536.awsdns-00.co.uk.
# offseclab.io name server ns-512.awsdns-00.net.
# offseclab.io name server ns-0.awsdns-00.com.
# offseclab.io name server ns-1024.awsdns-00.org.

whois awsdns-00.com | grep "Registrant Organization"       
# Registrant Organization: Amazon Technologies, Inc.

# FQDNに紐付いたIP
host www.offseclab.io
# www.offseclab.io has address 52.70.117.69

# IPに紐付いたFQDN、awsのec2インスタンスであることがわかる
host 52.70.117.69
# 69.117.70.52.in-addr.arpa domain name pointer ec2-52-70-117-69.compute-1.amazonaws.com

# IPを所有する組織
whois 52.70.117.69 | grep "OrgName"
# OrgName:        Amazon Technologies Inc.

```