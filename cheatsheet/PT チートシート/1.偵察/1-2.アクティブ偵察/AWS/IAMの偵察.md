> ターゲットのアカウントIDやアクセスキーなどが分かっている前提
> `get-caller-identity`を使う時は`--region`オプションで利用されていないリージョンを選んで実行すると防御側の監視を回避できる可能性がある
```sh
# ターゲットのアクセスキーなど設定して
aws configure --profile taget

# アカウントが有効になっているか確認して
aws --profile target sts get-caller-identity
# {
#     "UserId": "AIDAQOMAIGYUYNMOIF46I", <- 現在のユーザID
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/support/clouddesk-plove" <- 現在のユーザ名はclouddesk-ploveでsupportというパスに紐付いている
# }
```
> パスは組織構造に合わせてIDをグループ化するためのもの
> `sts get-caller-identity`は基本失敗することはないが、CloudTrailにログが残ったりアラートが飛んだりすることがあるので注意
> よりステルス性のある方法として`sts get-access-key-info`があり、ログが攻撃者側に記録される
```sh
# ターゲットのアクセスキーをオプションで指定してアカウントIDを取得
aws --profile challenge sts get-access-key-info --access-key-id AKIAQOMAIGYUVEHJ7WXM
{
    "Account": "123456789012"
}
```
> ステルス性のある別の方法としてCloudTrailイベント履歴にデフォルトで記録されないエラーメッセージを悪用する方法がある
> CloudTrailは（デフォルトでは？）データイベントとインサイトイベントは表示されないことになっている
```sh
# lambdaはデータイベントに属するため、今回の方法に利用できる
aws --profile target lambda invoke --function-name arn:aws:lambda:us-east-1:123456789012:function:nonexistent-function outfile
# An error occurred (AccessDeniedException) when calling the Invoke operation: User: arn:aws:iam::123456789012:user/support/clouddesk-plove is not authorized to perform: lambda:InvokeFunction on resource: arn:aws:lambda:us-east-1:123456789012:function:nonexistent-function because no resource-based policy allows the lambda:InvokeFunction action < アカウントIDやIDの種類（IAMユーザ、ロール）、コマンドを実行してるIDなどの情報が表示されてる！

```

### IAM権限のスコープ設定
```sh
# ユーザに適用されているインラインポリシーを表示
aws --profile target iam list-user-policies --user-name clouddesk-plove
# {
#     "PolicyNames": []
# }

# ユーザに適用されている管理ポリシーを表示
aws --profile target iam list-attached-user-policies --user-name clouddesk-plove
# {
#     {
#     "AttachedPolicies": [ <- 指定したユーザにiam:ListAttachedUserPoliciesを実行する権限があることが分かる
#         {
#             "PolicyName": "deny_challenges_access",
#             "PolicyArn": "arn:aws:iam::123456789012:policy/deny_challenges_access"
#         }
#     ]
# }
# }

```

### ユーザがグループからポリシーを継承しているか確認
```sh
# ユーザが属しているグループを確認
aws --profile target iam list-groups-for-user --user-name clouddesk-plove
# {
#     "Groups": [
#         {
#             "Path": "/support/",
#             "GroupName": "support", <- supportというグループ一つのみに属していることが分かる
#             "GroupId": "AGPAQOMAIGYUSHSVDSYIP",
#             "Arn": "arn:aws:iam::123456789012:group/support/support",
#         }
#     ]
# }

# グループに適用されているポリシーの確認
# インラインポリシー
aws --profile target iam list-group-policies --group-name support
# {
#     "PolicyNames": []
# }

# 管理ポリシー
aws --profile target iam list-attached-group-policies --group-name support
# {
#     "AttachedPolicies": [
#         {
#             "PolicyName": "SupportUser",
#             "PolicyArn": "arn:aws:iam::aws:policy/job-function/SupportUser" <- supportグループに属するユーザはSupportUserポリシーを持つことが分かる
#         }
#     ]
# }

# ポリシーの内容を調べる
aws --profile CompromisedJenkins iam get-user-policy --user-name jenkins-admin --policy-name jenkins-admin-role
# {
#     "UserName": "jenkins-admin",
#     "PolicyName": "jenkins-admin-role",
#     "PolicyDocument": {
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Sid": "",
#                 "Effect": "Allow",
#                 "Action": "*",
#                 "Resource": "*"
#             }
#         ]
#     }
# }

# もしくはポリシーのバージョンを調べて
aws --profile target iam list-policy-versions --policy-arn "arn:aws:iam::aws:policy/job-function/SupportUser"
# {
#     "Versions": [
#         {
#             "VersionId": "v8", <- 最新はv8
#             "IsDefaultVersion": true
#         },
#         {
#             "VersionId": "v7",
#             "IsDefaultVersion": false,
#         },
# ...

# バージョン情報を使ってポリシーの内容を取得
aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8
# {
#     "PolicyVersion": {
#         "Document": {
#             "Version": "2012-10-17",
#             "Statement": [
#                 {
#                     "Action": [
#                         "support:*",
#                         "acm:DescribeCertificate",
#                         "acm:GetCertificate",
#                         "acm:List*",
#                         "acm-pca:DescribeCertificateAuthority",
#                         "autoscaling:Describe*",
# ...
#                         "workdocs:Describe*",
#                         "workmail:Describe*",
#                         "workmail:Get*",
#                         "workspaces:Describe*"
#                     ],
#                     "Effect": "Allow",
#                     "Resource": "*"
#                 }
#             ]
#         },
#         "VersionId": "v8",
#         "IsDefaultVersion": true,
# ...
#     }
# }

# SupportUserポリシーのiamに対する権限を確認
aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8 | grep "iam"
#                         "iam:GenerateCredentialReport", <- その他、権限のあるアクション
#                         "iam:GenerateServiceLastAccessedDetails", <- その他、権限のあるアクション
#                         "iam:Get*", <- getから始まる任意のiamサブコマンドを利用可能
#                         "iam:List*", <- listから始まる任意のiamサブコマンドを利用可能

# list-, get-, generate-から始まるサブコマンドの確認
aws --profile target iam help | grep -E "list-|get-|generate-"

# 
aws --profile target iam get-account-summary | jq
# {
#     "SummaryMap": {
#         "GroupPolicySizeQuota": 5120,
#         "InstanceProfilesQuota": 1000,
#         "Policies": 8, <- ポリシーの数
#         "GroupsPerUserQuota": 10,
#         "InstanceProfiles": 0, <- EC2インスタンスの承認に必要？
#         "AttachedPoliciesPerUserQuota": 10,
#         "Users": 18, <- IAMユーザの数
#         "PoliciesQuota": 1500,
#         "Providers": 1, <- AWSの外部IDを管理するIDプロバイダの数？
#         "AccountMFAEnabled": 0, <- rootユーザのMFAが有効になっていないことが分かる
#         "AccessKeysPerUserQuota": 2,
#         "AssumeRolePolicySizeQuota": 2048,
#         "PolicyVersionsInUseQuota": 10000,
#         "GlobalEndpointTokenVersion": 1,
#         "VersionsPerPolicyQuota": 5,
#         "AttachedPoliciesPerGroupQuota": 10,
#         "PolicySizeQuota": 6144,
#         "Groups": 8, <- グループの数
#         "AccountSigningCertificatesPresent": 0,
#         "UsersQuota": 5000,
#         "ServerCertificatesQuota": 20, <- SSL/TLS暗号化を必要とするサービスに使用
#         "MFADevices": 0, <- MFAデバイスの数
#         "UserPolicySizeQuota": 2048,
#         "PolicyVersionsInUse": 27,
#         "ServerCertificates": 0,
#         "Roles": 20, <- ロールの数
#         "RolesQuota": 1000,
#         "SigningCertificatesPerUserQuota": 2,
#         "MFADevicesInUse": 0, <-  利用されているMFAデバイスの数？ 見つかった18人のユーザはいずれもMFAを利用していないことが分かる
#         "RolePolicySizeQuota": 10240,
#         "AttachedPoliciesPerRoleQuota": 10,
#         "AccountAccessKeysPresent": 0,
#         "GroupsQuota": 300
#     }
# }

# ユーザの列挙
aws --profile target iam list-users | tee  users.json
# {
#     "Users": [
#         {
#             "Path": "/admin/",
#             "UserName": "admin-alice",
#             "UserId": "AIDAQOMAIGYU3FWX3JOFP",
#             "Arn": "arn:aws:iam::123456789012:user/admin/admin-alice",
#         },
# ...

# グループの列挙
aws --profile target iam list-groups | tee groups.json
# {
#     "Groups": [
#         {
#             "Path": "/admin/",
#             "GroupName": "admin",
#             "GroupId": "AGPAQOMAIGYUXBR7QGLLN",
#             "Arn": "arn:aws:iam::123456789012:group/admin/admin",
#         },
# ...

# ロールの列挙
aws --profile target iam list-roles | tee roles.json
# {
#     "Roles": [
#         {
#             "Path": "/",
#             "RoleName": "aws-controltower-AdministratorExecutionRole",
#             "RoleId": "AROAQOMAIGYU6PUFJYD7W",
#             "Arn": "arn:aws:iam::123456789012:role/aws-controltower-AdministratorExecutionRole",
# ...

# 管理ポリシーの列挙
aws --profile target iam list-policies --scope Local --only-attached | tee policies.json
# {
#     "Policies": [
#         {
#             "PolicyName": "manage-credentials",
#             "PolicyId": "ANPAQOMAIGYU3LK3BHLGL",
#             "Arn": "arn:aws:iam::123456789012:policy/manage-credentials",
#             "Path": "/",
#             "DefaultVersionId": "v1",
#             "AttachmentCount": 1,
#             "PermissionsBoundaryUsageCount": 0,
#             "IsAttachable": true,
#             "UpdateDate": "2023-10-19T15:45:59+00:00"
#         },
# ...


# get-account-authorization-detailsで列挙を少し簡略化できる
# --filterを使ってUser、Role、 Group、LocalManagedPolicy、AWSManagedPolicyを含むスペース区切りの要素のリストを使用して結果をフィルタリングできる。AWS カスタム管理ポリシーには興味がないため、この値は省略する（フィルターに加えない）
# 1回のコマンドですべて列挙できるため、生成されるログはこっちのほうが少ない
aws --profile target iam get-account-authorization-details --filter User Group LocalManagedPolicy Role | tee account-authorization-details.json
# {
#     "UserDetailList": [
#         {
#             "Path": "/admin/",
#             "UserName": "admin-alice",
#             "UserId": "AIDAQOMAIGYU3FWX3JOFP",
#             "Arn": "arn:aws:iam::123456789012:user/admin/admin-alice",
#             "GroupList": [
#                 "amethyst_admin",
#                 "admin"
#             ],
#     ...
#     "GroupDetailList": [
#         {
#             "Path": "/admin/",
#             "GroupName": "admin",
#             "GroupId": "AGPAQOMAIGYUXBR7QGLLN",
#             "Arn": "arn:aws:iam::123456789012:group/admin/admin",
#             "GroupPolicyList": [],
#     ...
#     "RoleDetailList": [
#         {
#             "Path": "/",
#             "RoleName": "aws-controltower-AdministratorExecutionRole",
#             "RoleId": "AROAQOMAIGYU6PUFJYD7W",
#             "Arn": "arn:aws:iam::123456789012:role/aws-controltower-AdministratorExecutionRole",
#     ...
#     "Policies": [
#         {
#             "PolicyName": "ruby_admin",
#             "PolicyId": "ANPAQOMAIGYU3I3WDCID3",
#             "Arn": "arn:aws:iam::123456789012:policy/ruby/ruby_admin",
#             "Path": "/ruby/",
# ...

# JMESPathというjson用のクエリ言語で表示をわかりやすくできる
# filterはサーバ側で実行されるのに対してqueryの処理はクライアント側で実行されるという違いがある
aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[].UserName"
# [
#     "admin-alice",
#     "admin-cbarton",
#     "admin-srogers",
#     "admin-tstark",
#     "challenge",
#     "clouddesk-bob",
#     "clouddesk-fruiz",
#     "clouddesk-plove",
#     "dev-ballen",
#     "dev-csandiego",
#     "dev-ddory",
#     "dev-jreyes",
#     "dev-mmurdock",
#     "dev-mwindu",
#     "dev-prince",
#     "dev-rboggs",
#     "dev-shedgehog",
#     "monitoring"
# ]

# key, key, keyと並べることもできて
aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[0].[UserName,Path,GroupList]"
# [
#     "admin-alice",
#     "/admin/",
#     [
#         "admin"
#     ]
# ]

# 任意の識別子を指定することもできる
aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[0].{Name: UserName,Path: Path,Groups: GroupList}"
# {
#     "Name": "admin-alice",
#     "Path": "/admin/",
#     "Groups": [
#         "admin"
#     ]
# }

# adminをユーザ名に含むといった条件を指定することもできて
aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[?contains(UserName, 'admin')].{Name: UserName}"
# [
#     {
#         "Name": "admin-alice"
#     },
#     {
#         "Name": "admin-cbarton"
#     },
#     {
#         "Name": "admin-srogers"
#     },
# 
# ...

# 複数の条件も設定できる
aws --profile target iam get-account-authorization-details --filter User Group --query "{Users: UserDetailList[?Path=='/admin/'].UserName, Groups: GroupDetailList[?Path=='/admin/'].{Name: GroupName}}"
# {
#    "Users": [
#        "admin-alice"
#    ],
#    "Groups": [
#        {
#            "Name": "admin"
#        }
#    ]
# }



```


### 自動化
- ポリシー列挙の自動化にはpacuの`iam__bruteforce_permissions`モジュールやawsenum、enumerate-iamといったAWS列挙ツールを使うことで自動化できる