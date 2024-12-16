```sh
# .gitフォルダを見つけたら、リポジトリのチェックをすると良いものが見つかるかも
git status
# HEAD detached at 612ff57
# nothing to commit, working tree clean
# 
git log
# commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD -> master)
# Author: root <root@websrv1>
# Date:   Tue Sep 27 14:26:15 2022 +0000
# 
#     Removed staging script and internal network access
# 
# commit f82147bb0877fa6b5d8e80cf33da7b8f757d11dd
# Author: root <root@websrv1>
# Date:   Tue Sep 27 14:24:28 2022 +0000
# 
#     initial commit

# 過去のリポジトリが見つかったらshowで差異を確認可能
git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
# commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
# Author: root <root@websrv1>
# Date:   Tue Sep 27 14:26:15 2022 +0000
#
#     Removed staging script and internal network access
#
# diff --git a/fetch_current.sh b/fetch_current.sh
# deleted file mode 100644
# index 25667c7..0000000
# --- a/fetch_current.sh
# +++ /dev/null
# @@ -1,6 +0,0 @@
# -#!/bin/bash
# -
# -# Script to obtain the current state of the web app from the staging server
# -
# -sshpass -p "dqsTwTpZPn#nL" rsync john@192.168.50.245:/current_webapp/ /srv/www/wordpress/
# -

```