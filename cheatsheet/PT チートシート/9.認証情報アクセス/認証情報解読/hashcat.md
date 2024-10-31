```sh
# 辞書攻撃 = -a 0
hashcat -m 1400 -a 0 hash.txt password.lst

# ブルートフォース = -a 3
hashcat -m 1400 -a 3 hash.txt

# パスワードリストにルールを適用
# 過去結果を無視するには--potfile-disableを指定
hashcat -m 0 f621b6c9eab51a3e2f4e167fee4c6860 /usr/share/wordlists/rockyou.txt -r demo.rule --force -O

hashcat -m 13400 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule -O -w 3 -S
```
-mオプションの指定番号は[hash example](https://hashcat.net/wiki/doku.php?id=example_hashes)を参照

### ルールの作成について
```sh
# 定義済みルール
# /usr/share/hashcat/rulesにルールが保存されてる

# パスワードルール作成
# リストにあるパスワードの \echo $1: 末尾に1をつける
echo \$1 > demo.rule

# ルール適用
hashcat -r demo.rule --stdout demo.txt
# password1
# iloveyou1
# princess1
# rockyou1
# abc1231

# ルールは同じ行にまとめて書くと
kali@kali:~/passwordattacks$ cat demo1.rule 
# $1 c

# まとめて適用される
kali@kali:~/passwordattacks$ hashcat -r demo1.rule --stdout demo.txt
# Password1
# Iloveyou1
# Princess1
# Rockyou1
# Abc1231

# 別々に行に書くと
kali@kali:~/passwordattacks$ cat demo2.rule   
# $1
# c

# それぞれの別々に適用される
kali@kali:~/passwordattacks$ hashcat -r demo2.rule --stdout demo.txt
# password1
# Password
# iloveyou1
# Iloveyou
# princess1
# Princess
```
[ルールについて](https://hashcat.net/wiki/doku.php?id=rule_based_attack)