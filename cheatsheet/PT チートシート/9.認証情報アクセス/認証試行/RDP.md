```sh
xfreerdp /u:user /p:password /v:192.168.0.1 +clipboard /dynamic-resolution

xfreerdp /u:user /H:0e363213e37b94221497260b0bcb4fc /v:10.10.10.10 +clipboard /size:1920x1080

# connect to windows 7
xfreerdp /u:user /p:password /v:192.168.0.1 /dynamic-resolution /cert:ignore /workarea /tls-seclevel:0
```