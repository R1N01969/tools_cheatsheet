```sh
# ほぼほぼないかもだけど、sudoでどんなコマンドでも許可されているときは
# sudo -iでそのまま昇格可能
sudo -l
# [sudo] password for eve:
# Matching Defaults entries for eve on debian-privesc:
#     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

# User eve may run the following commands on debian-privesc:
#     (ALL : ALL) ALL

sudo -i
# [sudo] password for eve:

whoami
# root
```