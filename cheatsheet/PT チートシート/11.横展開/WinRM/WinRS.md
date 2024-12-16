
### cmd
```sh
# ドメインユーザがターゲットホストのAdministrators, Remote Management Usersグループに属している必要がある
winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
```

### Powershell
```sh
# 認証情報準備
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

# セッションを作成
New-PSSession -ComputerName 192.168.50.73 -Credential $credential
#  Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
# -- ----            ------------    ------------    -----         -----------------     ------------
#  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available

# 作成されたセッションのIDを指定して移動
Enter-PSSession 1
```