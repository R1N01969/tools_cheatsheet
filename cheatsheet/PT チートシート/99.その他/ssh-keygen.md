```sh
ssh-keygen
# Generating public/private ed25519 key pair.
# Enter file in which to save the key (/home/USER/.ssh/id_ed25519): fileup
# Enter passphrase (empty for no passphrase): 
# Enter same passphrase again: 
# Your identification has been saved in fileup
# Your public key has been saved in fileup.pub
# The key fingerprint is:
# SHA256:YmhYoXrdaK6ERy1OEqZBl5C6qwBrQTsdayUfpD5uMkQ USER@HOSTNAME
# The key's randomart image is:
# +--[ED25519 256]--+
# | oo.o.           |
# |...oo.           |
# |+E.+.o           |
# |*++=*+.          |
# |=***B.+ S        |
# |+O==.. .         |
# |+=+o.            |
# |+o+.             |
# |o .              |
# +----[SHA256]-----+
cat fileup.pub > authorized_keys

# 接続先の.ssh/authorized_keysをなんとかして上書きする

rm ~/.ssh/known_hosts

ssh -p 2222 -i fileup root@mountaindesserts.com
# The authenticity of host '[mountaindesserts.com]:2222 ([192.168.50.16]:2222)' can't be established.
# ED25519 key fingerprint is SHA256:R2JQNI3WJqpEehY2Iv9QdlMAoeB3jnPvjJqqfDZ3IXU.
# This key is not known by any other names
# Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
# ...
# root@76b77a6eae51:~#

```