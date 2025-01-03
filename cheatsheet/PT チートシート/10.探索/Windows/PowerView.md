```sh
Import-Module .\PowerView.ps1

# ユーザやグループの列挙コマンド
Get-NetDomain
Get-NetUser
Get-NetComputer

# 現在のユーザを管理者とするネットワーク内のホストを検索
Find-LocalAdminAccess
# ログインユーザの列挙コマンド
Get-NetSession -ComputerName files04 -Verbose
```

```sh
# アカウント情報より、アカウント名・パスワードの最終変更日時・最終ログイン日時を表示
Get-NetUser | select cn,pwdlastset,lastlogon
```

```sh
# グループ名の表示
Get-NetGroup | select cn

# 指定グループのメンバーを表示
Get-NetGroup "Sales Department" | select member
```

```sh
# OSとホスト名を表示
Get-NetComputer | select operatingsystem,dnshostname
```

```sh
Get-NetSession -ComputerName files04 -Verbose

# Get-NetSessionで使用するアクセス許可はレジストリのSrvsvcSessionInfoキーで定義
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
```

```sh
# ユーザに適用されているACE(Access Control Entry)を表示
Get-ObjectAcl -Identity stephanie
# （省略）
# ObjectDN              : CN=stephanie,CN=Users,DC=corp,DC=com
# ObjectSID             : S-1-5-21-1987370270-658905905-1781884369-1104
# ActiveDirectoryRights : GenericAll
# BinaryLength          : 36
# AceQualifier          : AccessAllowed
# IsCallback            : False
# OpaqueLength          : 0
# AccessMask            : 983551
# SecurityIdentifier    : S-1-5-21-1987370270-658905905-1781884369-519
# AceType               : AccessAllowed
# AceFlags              : ContainerInherit, Inherited
# IsInherited           : True
# InheritanceFlags      : ContainerInherit
# PropagationFlags      : None
# AuditFlags            : None
# （省略）

# SIDは読める形に変換可能
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
# CORP\stephanie <- ObjectSIDがstephanieに属してることがわかる
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-519
# CORP\Enterprise Admins <- ActiveDirectoryRightsの権限を持ってるユーザがわかる


# 権限がGenericAllなSIDを表示
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
# SecurityIdentifier                            ActiveDirectoryRights
# ------------------                            ---------------------
# S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
# S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
# S-1-5-32-548                                             GenericAll
# S-1-5-18                                                 GenericAll
# S-1-5-21-1987370270-658905905-1781884369-519             GenericAll

# SIDをまとめて変換
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
# CORP\Domain Admins
# CORP\stephanie
# BUILTIN\Account Operators
# Local System
# CORP\Enterprise Admins

# 利用可能な共有の列挙
Find-DomainShare
```

```sh
# 特定のSIDがGenericAllを持っている対象をObjectSIDを探す
Get-ObjectAcl | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | ? {$_.SecurityIdentifier -eq "S-1-5-21-1987370270-658905905-1781884369-1104" } | select ObjectSID,SecurityIdentifier,ActiveDirectoryRights
```