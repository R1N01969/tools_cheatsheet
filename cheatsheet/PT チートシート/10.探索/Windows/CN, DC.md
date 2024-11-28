```sh
# ADと通信する形式
LDAP://HostName[:PortNumber][/DistinguishedName]
```

### PDC Hostname
```sh
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
# 
# Forest                  : corp.com
# DomainControllers       : {DC1.corp.com}
# Children                : {}
# DomainMode              : Unknown
# DomainModeLevel         : 7
# Parent                  :
# PdcRoleOwner        : DC1.corp.com <- これ！！
# RidRoleOwner            : DC1.corp.com
# InfrastructureRoleOwner : DC1.corp.com
# Name                  	: corp.com
```

### DC
```sh
([adsi]'')
# distinguishedName : {DC=corp,DC=com}
# Path              :

([adsi]'').distinguishedName
# DC=corp,DC=com
```

### Sample Script
```sh
# define function
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}


# Store the domain object in the $domainObj variable
# $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Print the variable
# $domainObj

# Store the PdcRoleOwner name to the $PDC variable
# $PDC = $domainObj.PdcRoleOwner.Name

# Print hte $PDC variable
# $PDC

# Store the Distinguished Name variable into the $DN variable
# $DN = ([adsi]'').distinguishedName

# Print the $DN variable
# $DN

# $LDAP = "LDAP://$PDC/$DN"
# $LDAP

# $direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

# $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)

# 公式ドキュメント では、 samAccountType属性のさまざまな値が示されていますが、ここでは 0x30000000 (10 進数 805306368) から始めます。
# $dirsearcher.filter="samAccountType=805306368"
# $dirsearcher.filter="name=jeffadmin"

# $result = $dirsearcher.FindAll()

# Foreach($obj in $result)
# {
#     Foreach($prop in $obj.Properties)
#     {
        # $prop
        # $prop.memberof
#     }

#     Write-Host "-------------------------------"
# }

foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member} }

$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member
# CN=Development Department,DC=corp,DC=com
# CN=pete,CN=Users,DC=corp,DC=com
# CN=stephanie,CN=Users,DC=corp,DC=com

# net.exeで見つからなかったDevelopment Departmentが見つかっている
net group "Sales Department" /domain
# The request will be processed at a domain controller for domain corp.com.
# 
# Group name     Sales Department
# Comment
# 
# Members
# -------------------------------------------------------------------------------
# pete                     stephanie
# The command completed successfully.

$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"

$group.properties.member
# CN=jen,CN=Users,DC=corp,DC=com

$test = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Service Personnel))"
$test.properties.member
```