```sh
psql -h 192.168.231.63 -p 2345 -U postgres
# Password for user postgres: 
# psql (16.4 (Debian 16.4-1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
# SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
# Type "help" for help.

# データベース一覧の表示  
postgres-# \l
#     Name    |  Owner   | Encoding | Locale Provider |   Collate   |    Ctype    | ICU Locale | ICU Rules |   Access privileges   
# ------------+----------+----------+-----------------+-------------+-------------+------------+-----------+-----------------------
#  confluence | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
#  postgres   | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
#  template0  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | =c/postgres          +
#             |          |          |                 |             |             |            |           | postgres=CTc/postgres
#  template1  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | =c/postgres          +
#             |          |          |                 |             |             |            |           | postgres=CTc/postgres
# (4 rows)

# データベースの選択  
postgres-# \c confluence
# psql (16.4 (Debian 16.4-1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
# SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
# You are now connected to database "confluence" as user "postgres".

# テーブル一覧の表示  
postgres-# \dt;

# テーブル構造の表示  
postgres-# \d cwd_user;

# テーブル内のデータを一覧  
postgres-# select * from cwd_user;
```