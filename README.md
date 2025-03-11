# 加密工具

這個工具允許您使用Windows憑證存放區中的憑證進行檔案簽章和加解密操作，同時支援智慧卡和其他類型的憑證。它同時支援 RFC3161 時間戳記功能，並支援多種演算法與檔案格式。

## 功能

- 使用任何位於My存放區的憑證進行檔案簽章
- 支援多種雜湊演算法(SHA1, SHA256, SHA384, SHA512)，預設使用SHA384
- 簽章驗證
- 檔案加密
- 檔案解密 (支援.p7m, .cms, .pgp格式)
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
SmartFileCrypto sign <檔案路徑> [--cert=<證書識別碼>] [--sha1=<憑證指紋>] [--hash=<雜湊演算法>] [--timestamp[=<時間戳記伺服器URL>]]
```

範例：
```
SmartFileCrypto sign D:\文件\合約.pdf --sha1=A1B2C3D4E5F67890 --hash=SHA512 --timestamp=http://timestamp.digicert.com
```

如果未指定證書，系統會彈出Windows憑證選擇對話框（僅顯示具有數位簽章能力的證書）。
如果指定SHA1指紋，則直接使用該證書而不顯示選擇對話框。

這將產生一個檔案：
- `合約.pdf.p7s`：二進制簽章檔

### 驗證簽章

```
SmartFileCrypto verify <已簽章檔案路徑>
```

範例：
```
SmartFileCrypto verify D:\文件\合約.pdf.p7s
```

### 檔案加密

```
SmartFileCrypto encrypt <檔案路徑> [--cert=<證書識別碼>] [--sha1=<憑證指紋>]
```

範例：
```
SmartFileCrypto encrypt D:\文件\機密.docx --sha1=A1B2C3D4E5F67890
```

如果未指定證書，系統會彈出Windows憑證選擇對話框（僅顯示具有加密能力的證書）。
如果指定SHA1指紋，則直接使用該證書而不顯示選擇對話框。

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

支援的加密檔案格式：`.cms`、`.p7m`、`.pgp`

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
- GlobalSign: http://timestamp.globalsign.com
- Microsoft: http://timestamp.microsoft.com
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
A: 加密後的檔案會產生`.cms`副檔名，程式解密時支援`.cms`、`.p7m`和`.pgp`格式。

## 開發資訊

本專案由Cursor呼叫claude-3.7-sonnet-thinking進行開發。

## 注意事項

- 本工具使用 Windows 原生密碼學 API，而非 OpenSSL 或其他第三方庫
- 時間戳記服務預設使用 DigiCert 的免費服務，您可以使用 `--timestamp=URL` 參數指定其他服務
- 輸出格式與 Kleopatra 兼容，但不是標準的 PGP 格式 