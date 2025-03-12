# 加密工具

這個工具允許您使用Windows憑證存放區中的憑證進行檔案簽章和加解密操作，同時支援智慧卡和其他類型的憑證。它同時支援 RFC3161 時間戳記功能，並支援多種演算法與檔案格式。

## 功能

- 使用任何位於My存放區的憑證進行檔案簽章
- 支援多種雜湊演算法(SHA1, SHA256, SHA384, SHA512)，預設使用SHA384
- 簽章驗證
- 檔案加密 (支援憑證加密)
- 檔案解密 (支援.p7m, .cms格式)
- 支援 RFC3161 時間戳記
- 支援指定時間戳記伺服器
- 支援使用SHA1指紋指定憑證
- 智慧卡憑證增強識別
- 根據操作類型篩選證書選擇對話框
- 支援Windows憑證選擇對話框

## 系統需求

- Windows 10/11
- .NET 6.0 或更高版本
- 若使用智慧卡憑證，需要智慧卡讀卡機和驅動程式

## 編譯與安裝

1. 使用 Visual Studio 或 .NET CLI 編譯專案：

```
dotnet build -c Release
```

2. 將編譯好的檔案放在您選擇的位置

## 使用方式

### 查看所有可用憑證

可以使用以下命令列出所有可用的憑證及其SHA1指紋:

```
SmartFileCrypto list-certs
```

### 檔案簽章

```
SmartFileCrypto sign <檔案路徑> [--cert=<證書識別碼>] [--sha1=<憑證指紋>] [--hash=<雜湊演算法>] [--timestamp[=<時間戳記伺服器URL>]] [--include-content]
```

範例：
```
SmartFileCrypto sign D:\文件\合約.pdf --sha1=A1B2C3D4E5F67890 --hash=SHA512 --timestamp=http://timestamp.digicert.com
```

如果未指定證書，系統會彈出Windows憑證選擇對話框（僅顯示具有數位簽章能力的證書）。
如果指定SHA1指紋，則直接使用該證書而不顯示選擇對話框。
使用 `--include-content` 選項可將原始檔案內容包含在簽章中，預設為不包含（分離式簽章）。

這將產生一個檔案：
- `合約.pdf.p7s`：二進制簽章檔

### 驗證簽章

```
SmartFileCrypto verify <已簽章檔案路徑> [--extract-content] [--debug]
```

範例：
```
SmartFileCrypto verify D:\文件\合約.pdf.p7s
```

使用 `--extract-content` 選項可提取簽章中所包含的檔案內容（如果簽章包含內容）。
使用 `--debug` 選項可查看詳細的診斷訊息。

### 檔案加密

```
SmartFileCrypto encrypt <檔案路徑> [--cert=<證書識別碼>] [--sha1=<憑證指紋>] [--cert-file=<憑證檔案路徑>]
```

範例：
```
SmartFileCrypto encrypt D:\文件\機密.docx --sha1=A1B2C3D4E5F67890
```

或使用檔案中的憑證：
```
SmartFileCrypto encrypt D:\文件\機密.docx --cert-file=D:\憑證\公鑰.cer
```

如果未指定證書，系統會彈出Windows憑證選擇對話框（顯示所有具有公鑰的證書）。
如果指定SHA1指紋，則直接使用該證書而不顯示選擇對話框。
如果指定憑證檔案路徑，則從檔案載入憑證（支援.cer、.crt、.pem、.pfx、.p12等格式）。

這將產生一個檔案：
- `機密.docx.cms`：加密檔案

### 檔案解密

```
SmartFileCrypto decrypt <已加密檔案路徑>
```

範例：
```
SmartFileCrypto decrypt D:\文件\機密.docx.cms
```

支援的加密檔案格式：`.cms`、`.p7m`

## 指定雜湊演算法

您可以使用`--hash`參數指定雜湊演算法，支援的算法有：
- SHA1
- SHA256
- SHA384 (預設)
- SHA512

範例：
```
SmartFileCrypto sign 文件.pdf --hash=SHA512 --timestamp
```

## 指定時間戳記伺服器

您可以使用以下方式指定時間戳記伺服器：

```
SmartFileCrypto sign 文件.pdf --timestamp=http://timestamp.digicert.com
```

常用的時間戳記伺服器包括：
- DigiCert: http://timestamp.digicert.com
- Sectigo: http://timestamp.sectigo.com
- GlobalSign: http://timestamp.globalsign.com/tsa/r6advanced1
- Microsoft: http://timestamp.acs.microsoft.com
- Apple: http://timestamp.apple.com/ts01

## 憑證指定方式

有三種方式可以指定憑證：

1. 使用SHA1指紋（最精確）:
   ```
   SmartFileCrypto sign 文件.pdf --sha1=A1B2C3D4E5F67890
   ```

2. 使用證書主題或序號:
   ```
   SmartFileCrypto sign 文件.pdf --cert="王小明"
   ```

3. 不指定任何證書，使用Windows憑證選擇對話框:
   ```
   SmartFileCrypto sign 文件.pdf --timestamp
   ```

## 智慧卡支援

程式能夠自動識別各種來源的智慧卡憑證，包括：
- 使用Microsoft Smart Card Key Storage Provider的智慧卡
- 使用CryptoAPI加入的智慧卡
- 具有特定智慧卡OID的憑證
- 具有智慧卡登入能力的憑證

## 故障排除

如果遇到憑證操作問題：

1. 確認憑證是否有效且未過期
2. 確認您有存取憑證私鑰的權限
3. 如使用智慧卡：確認智慧卡讀卡機是否正確連接與驅動程式安裝
4. 如使用智慧卡：確認 PIN 碼未被鎖定
5. 檢查 Windows 事件日誌尋找相關錯誤

## 常見問題

**Q: 如何找到我的證書SHA1指紋？**
A: 使用 `SmartFileCrypto list-certs` 命令，或在Windows憑證管理器 (certmgr.msc) 中查看您的證書詳細資料。

**Q: 簽章驗證失敗怎麼辦？**
A: 確認您是否擁有簽署該檔案的證書，或該證書是否在信任的憑證鏈中。

**Q: 解密失敗怎麼辦？**
A: 確認您擁有解密所需的私鑰，且您有正確的權限。

**Q: 如何自動選擇憑證而不顯示對話框？**
A: 使用 `--sha1=` 參數指定精確的憑證指紋。

**Q: 加密檔案的副檔名是什麼？**
A: 加密後的檔案統一使用`.cms`副檔名，程式解密時支援`.cms`、`.p7m`格式。

**Q: 這個軟體安全嗎？**
A: 這個軟體使用AI生成，發布者不保證安全性質，用於學習用途(學習歷程)，基本功能姑且沒有問題。

**Q: 為甚麼Release版本的數位簽章不被信任？**
A: 我是用自然人憑證進行簽章的，新版的Windows並沒有把GCA根憑證加入受信任的根憑證授權單位。

**Q: 為甚麼自然人憑證不被認為是智慧卡？**
A: 其實我也很迷惑，但是那一大堆OID和字串辨認硬是沒有包含自然人憑證，我放棄了

**Q: 能夠在非Windows平台上使用嗎?**
A: 憑證的讀取依賴Windows的API，你可以讓AI改成使用PKCS#11的方式，但是我之前沒有成功，OpenSSL+PKCS11 engine無法讀取。(如果要用自然人憑證，Hicos好像Linux版本沒有PKCS#11 module)

## 開發資訊

本專案由Cursor呼叫claude-3.7-sonnet-thinking進行開發。