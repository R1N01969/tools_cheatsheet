### PSLoggedon
```sh
# 使用にはRemote Registryサービスの有効化が必要
# Remote RegistryサービスはWindows 8 以降の Windows ワークステーションでは既定では有効になっていないため注意
# Remote RegistryサービスはServer 2012 R2、2016 (1607)、2019 (1809)、Server 2022 (21H2) などのそれ以降の Windows Server オペレーティング システムでも、デフォルトで有効になっている。10分以上放置されるとサービスは停止するが、PsLoggedonを実行すると再度動作する
.\PsLoggedon.exe \\HOSTNAME
```