```sh
# プロファイル名を指定して設定をすると切り替えが楽
aws configure --profile attacker
# AWS Access Key ID []: AKIAQO...
# AWS Secret Access Key []: cOGzm...
# Default region name []: us-east-1
# Default output format []: json

# コマンドを実行するときにプロファイル名を指定する必要がある
aws --profile attacker sts get-caller-identity
```