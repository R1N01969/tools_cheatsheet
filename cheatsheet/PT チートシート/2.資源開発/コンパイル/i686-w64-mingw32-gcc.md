```sh
# windows以外でwindowsライブラリを含むソースコードをコンパイル
# winsock2.h, windows.hなど
i686-w64-mingw32-gcc source.c -o exploit.exe

# -lオプションで静的リンクの指定
i686-w64-mingw32-gcc source.c -o exploit.exe -lws2_32

# 実行はwineで
wine exploit.exe
```