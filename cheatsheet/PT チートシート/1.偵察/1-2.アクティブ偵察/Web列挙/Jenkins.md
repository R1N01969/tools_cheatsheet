```sh
msfconsole --quiet
msf6 > use auxiliary/scanner/http/jenkins_enum

set RHOSTS automation.offseclab.io

set TARGETURI /

msf6 auxiliary(scanner/http/jenkins_enum) > run
# [+] 198.18.53.73:80      - Jenkins Version 2.385
# [*] /script restricted (403)
# [*] /view/All/newJob restricted (403)
# [*] /asynchPeople/ restricted (403)
# [*] /systemInfo restricted (403)
# [*] Scanned 1 of 1 hosts (100% complete)
# [*] Auxiliary module execution completed

```