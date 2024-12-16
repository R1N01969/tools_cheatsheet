```sh
wpscan --url URL -e

wpscan --url URL -U admin -P /usr/share/wordlists/rockyou.txt

wpscan --url http://alvida-eatery.org/ -e --api-token 'TOKEN'

# 使用されているテーマやプラグインのバージョンも確認すると良い
wpscan --url http://192.168.150.244/ --enumerate p --plugins-detection aggressive

```