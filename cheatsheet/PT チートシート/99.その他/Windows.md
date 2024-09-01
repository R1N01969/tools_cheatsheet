```powershell
# コマンド実行してるのがcmdかpowershellか判別できる
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```