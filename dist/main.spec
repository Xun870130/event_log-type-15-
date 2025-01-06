# -*- mode: python ; coding: utf-8 -*-

# `Analysis` 部分定義了主腳本、依賴模組和附加資源等
a = Analysis(
    ['main.py'],                       # 主腳本檔案
    pathex=[],                          # 可選的附加模組路徑
    binaries=[],                        # 二進位文件，可添加 .dll、.so 檔等
    datas=[                             # 附加資料或資源
        ('smbios_type15.ini', '.')         # 包含 `JavaCLient.jar`，放置於主路徑下
    ],
    hiddenimports=[],                   # 需要隱含導入的模組（如果自動檢測不到時可以指定）
    hookspath=[],                       # 自訂 hook 路徑，用於改變特定模組的導入行為
    hooksconfig={},                     # 用於設定特定 hook 的選項
    runtime_hooks=[],                   # 在應用啟動時要執行的 Python 腳本（例如設定環境變量）
    excludes=[],                        # 不需要打包的模組
    noarchive=False,                    # 不壓縮程式碼為一個檔案，設為 `False` 代表使用單一檔案格式
    optimize=0,                         # 編譯優化等級（0 表示不優化）
)

# 建立 `PYZ` 壓縮的純 Python 模組
pyz = PYZ(a.pure)

# `EXE` 部分定義了打包成 .exe 文件的設定
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='event_log_analyzer',                        # 生成的可執行檔名稱為 main.exe
    debug=False,                        # 不啟用除錯模式（若為 True，會顯示更多錯誤訊息）
    bootloader_ignore_signals=False,    # 加載器不忽略信號，可接收 CTRL+C 等信號
    strip=False,                        # 不剝除 exe 文件中的 symbol table 資訊
    upx=True,                           # 使用 UPX 壓縮，減小檔案大小
    upx_exclude=[],                     # 可以指定不需要 UPX 壓縮的文件
    runtime_tmpdir=None,                # 在系統臨時文件夾提取資源
    console=True,                       # 顯示 console，方便除錯
    disable_windowed_traceback=False,   # 發生錯誤時顯示 traceback
    argv_emulation=False,               # 不模擬命令列參數
    target_arch=None,                   # 未指定特定的架構
    codesign_identity=None,             # 無簽名設定（僅適用於 macOS）
    entitlements_file=None,             # 無附加的權限設定文件（僅適用於 macOS）
    version=r"D:\VScode\project\event_log\version.txt"
     # 添加版本文件
)
