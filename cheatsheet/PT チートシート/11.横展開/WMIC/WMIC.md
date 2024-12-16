### cmd
```sh
# UACによるリモート操作の制限がローカルユーザには存在するが、ドメインユーザにはない
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
# Executing (Win32_Process)->Create()
# Method execution successful.
# Out Parameters:
# instance of __PARAMETERS
# {
#         ProcessId = 752; <- プロセスID
#         ReturnValue = 0; <- 戻り値0はプロセスが正常に作成されたことを意味する
# };

```

### Powershell
```sh
# 認証情報の準備
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

# コマンドの準備
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';

# 実行
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
# ProcessId ReturnValue PSComputerName
# --------- ----------- --------------
#     3712              0 192.168.50.73
```