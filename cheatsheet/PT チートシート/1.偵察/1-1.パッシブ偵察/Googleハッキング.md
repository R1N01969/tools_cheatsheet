```sh
intile:    指定した1つのキーワードを含むタイトルを検索   intitle:"hoge"
allintile: 指定した複数のキーワードを含むタイトルを検索  allintile:"hoge" "foo"

inurl:    指定した1つのキーワードを含むURLを検索        inurl:"hoge"
allinurl: 指定した複数のキーワードを含むURLを検索       allinurl:"hoge" "foo"

intext:    指定した1つのキーワードを含むページを検索     intext:"hoge"
allintext: 指定した複数のキーワードを含むページを検索    allintext:"hoge" "foo"

site:     指定したドメインを含むページを検索            site:"hoge.com"
link:     指定したリンクを含むページを検索              link:"https://www.hoge.com"
inanchor: 指定したキーワードを含むアンカーテキストを検索  inanchor:"hoge" "foo"
numrange: 指定した数値を検索                          numrange:100-1000
                                                   numrange:100
before,after 指定した日付を検索                (after:2024-08-15 before:2024-08-160)

filetype: 指定した拡張子のファイルを検索                filetype:"pdf"
拡張子例：pdf,doc,docx,csv,xls,xlsx,txt,rtx,odt,ppt,pptx,pptm,xml,klm,php,
        sql,sqlite,pdb,idb,cdb,sis,odb,env,cfg,conf,config,cfm,log,inf
```

```sh
# 演算子
-       排他           -site:hoge.com  site:hoge.comの結果を除いた中から検索
.       単ワイルドカード site:"h.ge.com"
\"      囲み           site:"hoge.com"
*       ワイルドカード   site:"hoge.*"
|, OR   or演算子       intext:"hoge" | intext:"foo"
&, AND  and演算子      intext:"hoge" & intext:"foo"
```