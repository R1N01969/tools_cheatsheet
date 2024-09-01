## Linux
```sh
echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 192.168.1.$ip; done > ips
onesixtyone -c community -i ips

# MIBツリー全体を列挙
snmpwalk -c public -v1 -t 10 192.168.1.1 -Oa

# Windowsユーザの列挙
snmpwalk -c public -v1 -t 10 192.168.1.1 -Oa 1.3.6.1.4.1.77.1.2.25

# 実行中のプロセスの列挙
snmpwalk -c public -v1 -t 10 192.168.1.1 -Oa 1.3.6.1.2.1.25.4.2.1.2

# インストールされているソフトウェアの列挙
snmpwalk -c public -v1 -t 10 192.168.1.1 -Oa 1.3.6.1.2.1.25.6.3.1.2

# TCPリスニングポートの列挙
snmpwalk -c public -v1 -t 10 192.168.1.1d -Oa 1.3.6.1.2.1.6.13.1.3
```