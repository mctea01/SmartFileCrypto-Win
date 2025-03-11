using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Windows.Forms;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Cms;
using System.Linq;

namespace SmartFileCrypto
{
    public class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length < 1)
            {
                PrintUsage();
                return;
            }

            string command = args[0].ToLower();
            
            try
            {
                switch (command)
                {
                    case "sign":
                        await HandleSignCommand(args);
                        break;

                    case "verify":
                        if (args.Length < 2)
                        {
                            Console.WriteLine("錯誤: 驗證命令需要指定檔案路徑");
                            PrintUsage();
                            return;
                        }
                        
                        // 找出檔案路徑（第一個非參數選項）
                        string verifyFilePath = FindFilePath(args, 1);
                        if (verifyFilePath == null)
                        {
                            Console.WriteLine("錯誤: 未指定有效的檔案路徑");
                            PrintUsage();
                            return;
                        }
                        
                        VerifySignature(verifyFilePath);
                        break;

                    case "encrypt":
                        await HandleEncryptCommand(args);
                        break;

                    case "decrypt":
                        if (args.Length < 2)
                        {
                            Console.WriteLine("錯誤: 解密命令需要指定檔案路徑");
                            PrintUsage();
                            return;
                        }
                        
                        // 找出檔案路徑（第一個非參數選項）
                        string decryptFilePath = FindFilePath(args, 1);
                        if (decryptFilePath == null)
                        {
                            Console.WriteLine("錯誤: 未指定有效的檔案路徑");
                            PrintUsage();
                            return;
                        }
                        
                        DecryptFile(decryptFilePath);
                        break;

                    case "list-certs":
                        ListCertificates();
                        break;

                    default:
                        Console.WriteLine($"未知命令: {command}");
                        PrintUsage();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"操作失敗: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"詳細錯誤: {ex.InnerException.Message}");
                }
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("使用方式:");
            Console.WriteLine("  SmartFileCrypto sign <檔案路徑> [--cert=<證書識別碼>] [--sha1=<憑證指紋>] [--hash=<雜湊演算法>] [--timestamp[=<時間戳記伺服器URL>]]");
            Console.WriteLine("  SmartFileCrypto verify <已簽章檔案路徑>");
            Console.WriteLine("  SmartFileCrypto encrypt <檔案路徑> [--cert=<證書識別碼>] [--sha1=<憑證指紋>]");
            Console.WriteLine("  SmartFileCrypto decrypt <已加密檔案路徑>");
            Console.WriteLine("  SmartFileCrypto list-certs");
            Console.WriteLine();
            Console.WriteLine("參數:");
            Console.WriteLine("  <檔案路徑>             要處理的檔案路徑");
            Console.WriteLine("  --cert=<證書識別碼>    以證書主題名稱或序號指定證書");
            Console.WriteLine("  --sha1=<憑證指紋>      以SHA1指紋指定證書");
            Console.WriteLine("  --hash=<雜湊演算法>    指定雜湊演算法 (SHA1, SHA256, SHA384, SHA512, 預設為SHA384)");
            Console.WriteLine("  --timestamp           添加時間戳記（預設使用DigiCert伺服器）");
            Console.WriteLine("  --timestamp=<URL>     添加時間戳記並指定時間戳記伺服器URL");
            Console.WriteLine();
            Console.WriteLine("注意事項:");
            Console.WriteLine("  * 參數順序可以任意調換，如 'encrypt --sha1=1234 檔案.txt' 或 'sign 檔案.txt --sha1=1234'");
            Console.WriteLine("  * 若未指定證書，將顯示證書選擇對話框");
            Console.WriteLine("  * 時間戳記伺服器預設為 http://timestamp.digicert.com");
            Console.WriteLine("  * 加密檔案將產生 .cms 副檔名的檔案");
            Console.WriteLine("  * 解密功能支援 .cms、.p7m 和 .pgp 副檔名的檔案");
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPTUI_SELECTCERTIFICATE_STRUCT
        {
            public uint dwSize;
            public IntPtr hwndParent;
            public uint dwFlags;
            public string szTitle;
            public uint dwDontUseColumn;
            public string szDisplayString;
            public IntPtr pFilterCallback;
            public IntPtr pDisplayCallback;
            public IntPtr pvCallbackData;
            public uint cDisplayStores;
            public IntPtr rghDisplayStores;
            public uint cStores;
            public IntPtr rghStores;
            public uint cPropSheetPages;
            public IntPtr rgPropSheetPages;
            public IntPtr hSelectedCertStore;
            public IntPtr pSelectedCertContext;
        }

        [DllImport("cryptui.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CryptUIDlgSelectCertificateW(
            ref CRYPTUI_SELECTCERTIFICATE_STRUCT pcsc);

        private static X509Certificate2 SelectCertificateFromUI(string operation = null)
        {
            // 打開個人存放區
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                // 準備憑證列表
                X509Certificate2Collection collection = new X509Certificate2Collection();
                X509Certificate2Collection filteredCollection = new X509Certificate2Collection();
                
                // 先加入所有證書以供稍後篩選
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        collection.Add(cert);
                    }
                }

                if (collection.Count == 0)
                {
                    throw new Exception("找不到任何具有私鑰的憑證。");
                }

                // 根據操作過濾證書
                if (operation == "sign")
                {
                    // 僅選擇具有數位簽章能力的證書
                    foreach (X509Certificate2 cert in collection)
                    {
                        bool hasDigitalSignature = false;
                        foreach (X509Extension ext in cert.Extensions)
                        {
                            if (ext is X509KeyUsageExtension keyUsage)
                            {
                                if ((keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == X509KeyUsageFlags.DigitalSignature)
                                {
                                    hasDigitalSignature = true;
                                    break;
                                }
                            }
                        }
                        
                        if (hasDigitalSignature)
                        {
                            filteredCollection.Add(cert);
                        }
                    }
                    
                    // 如果沒有符合條件的證書，顯示錯誤訊息
                    if (filteredCollection.Count == 0)
                    {
                        throw new Exception("找不到任何具有數位簽章能力的憑證。");
                    }
                }
                else if (operation == "encrypt")
                {
                    // 僅選擇具有金鑰加密或資料加密能力的證書
                    foreach (X509Certificate2 cert in collection)
                    {
                        bool hasEncryption = false;
                        foreach (X509Extension ext in cert.Extensions)
                        {
                            if (ext is X509KeyUsageExtension keyUsage)
                            {
                                if ((keyUsage.KeyUsages & X509KeyUsageFlags.KeyEncipherment) == X509KeyUsageFlags.KeyEncipherment ||
                                    (keyUsage.KeyUsages & X509KeyUsageFlags.DataEncipherment) == X509KeyUsageFlags.DataEncipherment)
                                {
                                    hasEncryption = true;
                                    break;
                                }
                            }
                        }
                        
                        if (hasEncryption)
                        {
                            filteredCollection.Add(cert);
                        }
                    }
                    
                    // 如果沒有符合條件的證書，顯示錯誤訊息
                    if (filteredCollection.Count == 0)
                    {
                        throw new Exception("找不到任何具有加密能力的憑證。");
                    }
                }
                else
                {
                    // 若沒有特定操作，顯示所有證書
                    filteredCollection = collection;
                }

                // 設定對話框標題和提示訊息
                string title = "選擇憑證";
                string message = "請選擇要使用的憑證";
                
                if (operation == "sign")
                {
                    title = "選擇簽署憑證";
                    message = "請選擇要用於簽署文件的憑證 (僅顯示具有數位簽章能力的憑證)";
                }
                else if (operation == "encrypt")
                {
                    title = "選擇加密憑證";
                    message = "請選擇要用於加密文件的憑證 (僅顯示具有加密能力的憑證)";
                }

                // 使用X509Certificate2UI類別從正確的命名空間
                X509Certificate2Collection selected = X509Certificate2UI.SelectFromCollection(
                    filteredCollection,
                    title,
                    message,
                    X509SelectionFlag.SingleSelection);

                if (selected.Count > 0)
                {
                    return new X509Certificate2(selected[0]);
                }
                else
                {
                    throw new Exception("未選擇任何憑證。");
                }
            }
        }

        private static X509Certificate2 FindCertificate(string identifier, string operation = null)
        {
            // 如果未提供識別碼，顯示選擇對話框
            if (string.IsNullOrEmpty(identifier))
            {
                return SelectCertificateFromUI(operation);
            }

            Console.WriteLine($"正在尋找證書: {identifier}");

            // 嘗試從個人存放區尋找證書
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                // 處理SHA1指紋 (不區分大小寫並移除空格和冒號)
                string cleanIdentifier = identifier.Replace(" ", "").Replace(":", "").Replace("-", "").ToLowerInvariant();
                Console.WriteLine($"清理後的識別碼: {cleanIdentifier}");

                // 先檢查是否有完全匹配的指紋
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        string thumbprint = cert.Thumbprint.Replace(" ", "").Replace(":", "").Replace("-", "").ToLowerInvariant();
                        
                        // 偵錯輸出
                        Console.WriteLine($"比對證書: {cert.Subject}");
                        Console.WriteLine($"SHA1指紋: {thumbprint}");
                        
                        if (string.Equals(thumbprint, cleanIdentifier, StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("找到完全匹配的SHA1指紋證書!");
                            return new X509Certificate2(cert);
                        }
                    }
                }

                // 如果沒有找到完全匹配的指紋，嘗試其他匹配方式
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        if (cert.Subject.Contains(identifier) ||
                            cert.SerialNumber.Equals(identifier, StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine($"找到匹配的證書 (通過主題或序號): {cert.Subject}");
                            return new X509Certificate2(cert);
                        }
                    }
                }
            }

            // 如果找不到證書，回到選擇對話框
            Console.WriteLine($"找不到符合識別碼 '{identifier}' 的憑證，開啟選擇對話框...");
            return SelectCertificateFromUI(operation);
        }

        private static void ListCertificates()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                
                Console.WriteLine("可用的憑證:");
                Console.WriteLine("---------------------------------------------------");
                bool foundAny = false;
                
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        foundAny = true;
                        Console.WriteLine($"主題: {cert.Subject}");
                        Console.WriteLine($"發行者: {cert.Issuer}");
                        Console.WriteLine($"序號: {cert.SerialNumber}");
                        Console.WriteLine($"SHA1指紋: {cert.Thumbprint}");
                        Console.WriteLine($"有效期: {cert.NotBefore} 至 {cert.NotAfter}");
                        
                        // 顯示是否為智慧卡憑證
                        bool isSmartCard = IsSmartCardCertificate(cert);
                        Console.WriteLine($"智慧卡憑證: {(isSmartCard ? "是" : "否")}");
                        
                        Console.WriteLine("---------------------------------------------------");
                    }
                }
                
                if (!foundAny)
                {
                    Console.WriteLine("未找到任何具有私鑰的憑證。");
                }
            }
        }

        private static bool IsSmartCardCertificate(X509Certificate2 cert)
        {
            try
            {
                // 首先檢查 CNG Key Storage Provider
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    if (rsa is RSACng rsaCng)
                    {
                        string providerName = rsaCng.Key.Provider.ToString();
                        if (providerName.Contains("Smart Card"))
                        {
                            return true;
                        }
                    }
                }

                // 如果 CNG 判斷不是智慧卡，檢查其他特徵
                
                // 1. 檢查擴展屬性，尋找智慧卡相關的OID或標示
                foreach (var extension in cert.Extensions)
                {
                    // 某些智慧卡證書可能有特殊的擴展
                    if (extension.Oid.Value == "1.3.6.1.4.1.311.20.2")  // Smart Card Logon OID
                    {
                        return true;
                    }
                }
                
                // 2. 檢查憑證主題是否包含智慧卡相關資訊
                if (cert.Subject.Contains("Smart Card") || 
                    cert.Subject.Contains("SmartCard") || 
                    cert.Subject.Contains("PIV") ||
                    cert.Subject.ToLowerInvariant().Contains("card"))
                {
                    return true;
                }
                
                // 3. 檢查頒發者是否為已知的智慧卡憑證頒發者
                if (cert.Issuer.Contains("Smart Card") || 
                    cert.Issuer.Contains("PIV") ||
                    cert.Issuer.ToLowerInvariant().Contains("card"))
                {
                    return true;
                }
                
                // 4. 檢查增強型金鑰使用法(EKU)是否含智慧卡登入
                foreach (var extension in cert.Extensions)
                {
                    if (extension is X509EnhancedKeyUsageExtension eku)
                    {
                        foreach (var oid in eku.EnhancedKeyUsages)
                        {
                            // 智慧卡登入 OID
                            if (oid.Value == "1.3.6.1.4.1.311.20.2.2")
                            {
                                return true;
                            }
                        }
                    }
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static async Task HandleSignCommand(string[] args)
        {
            // 處理簽名命令
            // 檢查參數
            if (args.Length < 2)
            {
                Console.WriteLine("錯誤: 未指定檔案");
                PrintUsage();
                return;
            }
            
            // 查找檔案路徑
            string filePath = FindFilePath(args, 1);
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                Console.WriteLine($"錯誤: 檔案 '{filePath}' 不存在");
                return;
            }
            
            // 檢查是否指定證書
            string certIdentifier = null;
            bool useTimestamp = false;
            string tsaUrl = null;
            string hashAlgorithm = "SHA384"; // 預設使用SHA384
            
            for (int i = 1; i < args.Length; i++)
            {
                string arg = args[i].ToLower();
                
                if (arg.StartsWith("--cert=") || arg.StartsWith("-c="))
                {
                    certIdentifier = arg.Split('=')[1];
                }
                else if (arg.StartsWith("--sha1="))
                {
                    certIdentifier = arg.Split('=')[1];
                }
                else if (arg.StartsWith("--hash="))
                {
                    hashAlgorithm = arg.Split('=')[1].ToUpper();
                    // 驗證雜湊演算法是否支援
                    if (!new[] { "SHA1", "SHA256", "SHA384", "SHA512" }.Contains(hashAlgorithm))
                    {
                        Console.WriteLine($"錯誤: 不支援的雜湊演算法 '{hashAlgorithm}'，將使用預設值 SHA384");
                        hashAlgorithm = "SHA384";
                    }
                }
                else if (arg == "--timestamp" || arg == "-t")
                {
                    useTimestamp = true;
                }
                else if (arg.StartsWith("--timestamp=") || arg.StartsWith("-t="))
                {
                    useTimestamp = true;
                    tsaUrl = arg.Split('=')[1];
                }
            }
            
            // 簽署檔案
            await SignFile(filePath, certIdentifier, useTimestamp, tsaUrl, hashAlgorithm);
        }
        
        private static async Task HandleEncryptCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("錯誤: 加密命令需要指定檔案路徑");
                PrintUsage();
                return;
            }
            
            // 預設參數
            string certIdentifier = null;
            string filePath = null;
            
            // 解析所有參數
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i].StartsWith("--"))
                {
                    // 處理選項參數
                    if (args[i].StartsWith("--cert="))
                    {
                        certIdentifier = args[i].Substring("--cert=".Length);
                    }
                    else if (args[i].StartsWith("--sha1="))
                    {
                        certIdentifier = args[i].Substring("--sha1=".Length);
                    }
                }
                else if (filePath == null)
                {
                    // 不是選項參數，且尚未設置檔案路徑
                    filePath = args[i];
                }
                else if (certIdentifier == null)
                {
                    // 向後兼容：舊格式的命令行參數
                    certIdentifier = args[i];
                }
            }
            
            // 檢查必要參數
            if (filePath == null)
            {
                Console.WriteLine("錯誤: 未指定檔案路徑");
                PrintUsage();
                return;
            }
            
            EncryptFile(filePath, certIdentifier);
        }
        
        // 新增輔助方法來在參數列表中尋找檔案路徑
        private static string FindFilePath(string[] args, int startIndex)
        {
            for (int i = startIndex; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--"))
                {
                    // 不是選項參數，假設為檔案路徑
                    return args[i];
                }
            }
            return null;
        }

        private static async Task SignFile(string filePath, string certIdentifier, bool useTimestamp, string tsaUrl, string hashAlgorithm)
        {
            try
            {
                // 讀取要簽名的文件
                byte[] fileContent = File.ReadAllBytes(filePath);
                
                // 查找指定的證書
                X509Certificate2 certificate = null;
                if (string.IsNullOrEmpty(certIdentifier))
                {
                    certificate = SelectCertificateFromUI("sign");
                    if (certificate == null)
                    {
                        Console.WriteLine("未選擇證書，簽名已取消");
                        return;
                    }
                }
                else
                {
                    // 直接查找證書，找不到才顯示選擇對話框
                    certificate = FindCertificateDirectly(certIdentifier);
                    if (certificate == null)
                    {
                        Console.WriteLine($"找不到符合 '{certIdentifier}' 的證書，開啟選擇對話框...");
                        certificate = SelectCertificateFromUI("sign");
                        if (certificate == null)
                        {
                            Console.WriteLine("未選擇證書，簽名已取消");
                            return;
                        }
                    }
                }
                
                Console.WriteLine($"使用證書: {certificate.Subject}");
                Console.WriteLine($"智慧卡憑證: {(IsSmartCardCertificate(certificate) ? "是" : "否")}");
                Console.WriteLine($"正在簽署檔案: {Path.GetFileName(filePath)}");
                Console.WriteLine($"使用雜湊演算法: {hashAlgorithm}");
                
                // 建立CMS簽名
                ContentInfo contentInfo = new ContentInfo(fileContent);
                SignedCms signedCms = new SignedCms(contentInfo, true); // detached = true
                
                // 創建簽名者信息
                CmsSigner signer = new CmsSigner(certificate);
                signer.IncludeOption = X509IncludeOption.EndCertOnly;
                
                // 設定雜湊演算法
                switch (hashAlgorithm)
                {
                    case "SHA1":
                        signer.DigestAlgorithm = new Oid("1.3.14.3.2.26"); // SHA1
                        break;
                    case "SHA256":
                        signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"); // SHA256
                        break;
                    case "SHA384":
                        signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.2"); // SHA384
                        break;
                    case "SHA512":
                        signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.3"); // SHA512
                        break;
                    default:
                        // 使用預設
                        signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.2"); // SHA384
                        break;
                }
                
                // 簽署檔案
                signedCms.ComputeSignature(signer);
                byte[] signature = signedCms.Encode();
                
                // 如果需要，添加時間戳記
                if (useTimestamp)
                {
                    signature = await AddTimestamp(signature, tsaUrl, hashAlgorithm);
                }
                
                // 儲存簽章到輸出檔案
                string outputPath = filePath + ".p7s";
                File.WriteAllBytes(outputPath, signature);
                Console.WriteLine($"已簽署檔案並存儲為: {outputPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"簽名失敗: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"詳細錯誤: {ex.InnerException.Message}");
                }
            }
        }
        
        private static async Task<byte[]> AddTimestamp(byte[] signature, string tsaUrl, string hashAlgorithm)
        {
            if (string.IsNullOrEmpty(tsaUrl))
            {
                // 如果未指定時間戳記伺服器，則使用預設伺服器
                tsaUrl = "http://timestamp.digicert.com";
            }

            Console.WriteLine($"使用時間戳記伺服器: {tsaUrl}");

            try
            {
                // 計算簽章的雜湊值
                byte[] hash;
                
                // 根據指定的雜湊演算法建立對應的雜湊物件
                using (HashAlgorithm hasher = CreateHashAlgorithm(hashAlgorithm))
                {
                    hash = hasher.ComputeHash(signature);
                }

                // 使用 BouncyCastle 建立時間戳記請求
                TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
                requestGenerator.SetCertReq(true);

                // 設定雜湊演算法的OID
                string hashOid = GetHashAlgorithmOid(hashAlgorithm);
                TimeStampRequest request = requestGenerator.Generate(hashOid, hash);
                byte[] requestBytes = request.GetEncoded();

                Console.WriteLine("正在向時間戳記伺服器發送請求...");
                Console.WriteLine($"時間戳記請求大小: {requestBytes.Length} 字節");
                Console.WriteLine($"雜湊演算法: {hashAlgorithm}");

                // 發送時間戳記請求
                HttpClient client = new HttpClient();
                
                // 建立包含二進制內容的HttpContent
                ByteArrayContent content = new ByteArrayContent(requestBytes);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");
                
                // 傳送請求到時間戳記伺服器
                HttpResponseMessage response = await client.PostAsync(tsaUrl, content);
                
                if (response.IsSuccessStatusCode)
                {
                    byte[] tsResponse = await response.Content.ReadAsByteArrayAsync();
                    Console.WriteLine($"已收到時間戳記回應，大小: {tsResponse.Length} 位元組");

                    if (tsResponse == null || tsResponse.Length == 0)
                    {
                        Console.WriteLine("錯誤：從時間戳記伺服器收到空回應");
                        return signature;
                    }

                    // 首先嘗試用RFC 3161標準處理時間戳記
                    try
                    {
                        // 解析時間戳記回應
                        TimeStampResponse tsResp = new TimeStampResponse(tsResponse);
                        TimeStampToken tsToken = tsResp.TimeStampToken;

                        if (tsToken == null)
                        {
                            Console.WriteLine("無法從回應中獲取時間戳記令牌，將嘗試其他格式");
                            // 如果RFC 3161處理失敗，嘗試其他格式
                            return AddOtherTimestamp(signature, tsResponse);
                        }

                        // 提取時間戳記資訊
                        DateTime timestampTime = tsToken.TimeStampInfo.GenTime;
                        Console.WriteLine($"時間戳記時間: {timestampTime}");

                        // 從TimeStampToken提取DER編碼
                        byte[] tokenBytes = tsToken.GetEncoded();
                        
                        // 建立SignedCms物件
                        SignedCms signedCms = new SignedCms();
                        signedCms.Decode(signature);
                        
                        // 獲取簽名者並添加時間戳記
                        SignerInfo signer = signedCms.SignerInfos[0];
                        
                        // 建立RFC 3161時間戳記屬性
                        Oid timestampOid = new Oid("1.2.840.113549.1.9.16.2.14"); // RFC 3161 OID
                        AsnEncodedData timestampAttribute = new AsnEncodedData(timestampOid, tokenBytes);
                        signer.AddUnsignedAttribute(timestampAttribute);
                        
                        Console.WriteLine("RFC 3161時間戳記已添加到簽章中");
                        return signedCms.Encode();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"RFC 3161時間戳記處理失敗: {ex.Message}");
                        Console.WriteLine("嘗試使用其他格式...");
                        // 如果RFC 3161處理失敗，嘗試其他格式
                        return AddOtherTimestamp(signature, tsResponse);
                    }
                }
                else
                {
                    // 如果請求失敗，顯示錯誤訊息
                    Console.WriteLine($"時間戳記請求失敗: {response.StatusCode} {response.ReasonPhrase}");
                    return signature;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"時間戳記處理出錯: {ex.Message}");
                return signature;
            }
        }

        // 用於處理其他格式時間戳記的方法
        private static byte[] AddOtherTimestamp(byte[] signature, byte[] tsResponse)
        {
            try
            {
                Console.WriteLine("使用其他OID處理時間戳記...");
                
                // 建立SignedCms物件
                SignedCms signedCms = new SignedCms();
                signedCms.Decode(signature);
                
                // 獲取簽名者
                SignerInfo signer = signedCms.SignerInfos[0];
                
                // 其他時間戳記使用的OID
                Oid msTimestampOid = new Oid("1.3.6.1.4.1.311.3.3.1");
                
                // 建立時間戳記屬性
                AsnEncodedData msTimestampAttribute = new AsnEncodedData(msTimestampOid, tsResponse);
                signer.AddUnsignedAttribute(msTimestampAttribute);
                
                Console.WriteLine("其他格式時間戳記已添加到簽章中");
                return signedCms.Encode();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"其他時間戳記處理失敗: {ex.Message}");
                return signature;
            }
        }

        private static void VerifySignature(string filePath)
        {
            try
            {
                // 讀取簽章檔案內容
                byte[] signatureBytes = File.ReadAllBytes(filePath);
                Console.WriteLine($"已讀取二進制簽章檔案 ({signatureBytes.Length} 字節)");
                
                // 檢查對應的原始檔案是否存在
                string originalFilePath = filePath.Replace(".p7s", "");
                if (!File.Exists(originalFilePath))
                {
                    Console.WriteLine($"警告: 找不到原始檔案 '{originalFilePath}' ，將嘗試直接解析簽名");
                }
                else
                {
                    Console.WriteLine($"已找到原始檔案: {originalFilePath}");
                }
                
                // 準備解碼簽章
                SignedCms signedCms = new SignedCms();
                
                try
                {
                    // 嘗試解碼簽章
                    Console.WriteLine("正在驗證簽章...");
                    if (File.Exists(originalFilePath))
                    {
                        // 讀取原始檔案內容
                        byte[] contentBytes = File.ReadAllBytes(originalFilePath);
                        ContentInfo contentInfo = new ContentInfo(contentBytes);
                        signedCms = new SignedCms(contentInfo, true); // detached = true
                        signedCms.Decode(signatureBytes);
                    }
                    else
                    {
                        // 當原始檔案不存在時，嘗試非分離式簽名解碼
                        signedCms.Decode(signatureBytes);
                    }
                }
                catch (Exception decodeEx)
                {
                    Console.WriteLine($"簽章解碼錯誤: {decodeEx.Message}");
                    return;
                }
                
                try
                {
                    // 驗證簽章
                    signedCms.CheckSignature(true); // 驗證所有簽名
                    
                    if (signedCms.SignerInfos.Count > 0)
                    {
                        SignerInfo signer = signedCms.SignerInfos[0];
                        X509Certificate2 signerCert = signer.Certificate;
                        
                        if (signerCert != null)
                        {
                            Console.WriteLine($"簽署者: {signerCert.Subject}");
                            Console.WriteLine($"證書指紋: {BitConverter.ToString(signerCert.GetCertHash()).Replace("-", "")}");
                            Console.WriteLine($"證書有效期: {signerCert.NotBefore} 至 {signerCert.NotAfter}");
                        }
                        
                        // 檢查時間戳記
                        DateTime? signingTime = GetSigningTime(signer);
                        if (signingTime.HasValue)
                        {
                            Console.WriteLine($"簽署時間: {signingTime.Value}");
                        }
                        
                        // 檢查RFC 3161時間戳記
                        bool foundTimestamp = false;
                        foreach (CryptographicAttributeObject attr in signer.UnsignedAttributes)
                        {
                            if (attr.Oid.Value == "1.2.840.113549.1.9.16.2.14") // RFC 3161 timestamp
                            {
                                foundTimestamp = true;
                                Console.WriteLine("發現RFC 3161時間戳記");
                                try
                                {
                                    // 嘗試使用BouncyCastle解析RFC 3161時間戳記
                                    AsnEncodedData asnData = attr.Values[0];
                                    byte[] tokenBytes = asnData.RawData;
                                    
                                    TimeStampToken timestamp = new TimeStampToken(
                                        new CmsSignedData(tokenBytes));
                                    
                                    TimeStampTokenInfo info = timestamp.TimeStampInfo;
                                    Console.WriteLine($"時間戳記時間: {info.GenTime}");
                                    Console.WriteLine($"時間戳記序號: {info.SerialNumber}");
                                    Console.WriteLine($"時間戳記策略: {info.Policy}");
                                    
                                    // 獲取時間戳記簽發者信息
                                    if (timestamp.SignerID != null)
                                    {
                                        Console.WriteLine($"時間戳記簽發者: {timestamp.SignerID.Issuer}");
                                    }
                                }
                                catch (Exception rfc3161Ex)
                                {
                                    Console.WriteLine($"RFC 3161時間戳記處理錯誤: {rfc3161Ex.Message}");
                                }
                            }
                            else if (attr.Oid.Value == "1.3.6.1.4.1.311.3.3.1") // Special Timestamp
                            {
                                foundTimestamp = true;
                                Console.WriteLine("發現其他格式時間戳記");
                                try
                                {
                                    // 嘗試處理其他時間戳記
                                    AsnEncodedData asnData = attr.Values[0];
                                    Asn1InputStream asnInputStream = new Asn1InputStream(asnData.RawData);
                                    Asn1Object asn1Object = asnInputStream.ReadObject();
                                    
                                    if (asn1Object != null)
                                    {
                                        // 嘗試解析時間戳記值
                                        Asn1Sequence sequence = Asn1Sequence.GetInstance(asn1Object);
                                        if (sequence != null && sequence.Count >= 1)
                                        {
                                            Console.WriteLine($"其他格式時間戳記資訊:");
                                            try
                                            {
                                                // 從序列中獲取GeneralizedTime
                                                if (sequence.Count >= 3 && sequence[2] is DerGeneralizedTime)
                                                {
                                                    DerGeneralizedTime timeValue = (DerGeneralizedTime)sequence[2];
                                                    Console.WriteLine($"時間戳記時間: {timeValue.ToDateTime()}");
                                                }
                                            }
                                            catch (Exception timeEx)
                                            {
                                                Console.WriteLine($"時間戳記時間解析錯誤: {timeEx.Message}");
                                            }
                                        }
                                    }
                                }
                                catch (Exception tsEx)
                                {
                                    Console.WriteLine($"處理其他格式時間戳記錯誤: {tsEx.Message}");
                                }
                            }
                        }
                        
                        if (!foundTimestamp)
                        {
                            Console.WriteLine("未發現時間戳記");
                        }
                    }
                    
                    Console.WriteLine("簽章驗證成功!");
                }
                catch (Exception verifyEx)
                {
                    Console.WriteLine($"簽章驗證失敗: {verifyEx.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"處理簽章時發生錯誤: {ex.Message}");
            }
        }

        // 新增幫助方法來獲取簽署時間
        private static DateTime? GetSigningTime(SignerInfo signerInfo)
        {
            if (signerInfo.SignedAttributes.Count > 0)
            {
                foreach (CryptographicAttributeObject attr in signerInfo.SignedAttributes)
                {
                    if (attr.Oid.Value == "1.2.840.113549.1.9.5") // SigningTime OID
                    {
                        if (attr.Values.Count > 0)
                        {
                            Pkcs9SigningTime signingTime = new Pkcs9SigningTime();
                            signingTime.CopyFrom(attr.Values[0]);
                            return signingTime.SigningTime;
                        }
                    }
                }
            }
            return null;
        }

        private static void EncryptFile(string filePath, string certIdentifier)
        {
            try
            {
                // 讀取要加密的檔案
                byte[] fileContent = File.ReadAllBytes(filePath);
                
                // 查找證書
                X509Certificate2 certificate = null;
                if (string.IsNullOrEmpty(certIdentifier))
                {
                    certificate = SelectCertificateFromUI("encrypt");
                    if (certificate == null)
                    {
                        Console.WriteLine("未選擇證書，加密已取消");
                        return;
                    }
                }
                else
                {
                    // 直接查找指定的憑證指紋，找不到才顯示選擇對話框
                    certificate = FindCertificateDirectly(certIdentifier);
                    if (certificate == null)
                    {
                        Console.WriteLine($"找不到符合 '{certIdentifier}' 的證書，開啟選擇對話框...");
                        certificate = SelectCertificateFromUI("encrypt");
                        if (certificate == null)
                        {
                            Console.WriteLine("未選擇證書，加密已取消");
                            return;
                        }
                    }
                }
                
                Console.WriteLine($"使用證書: {certificate.Subject}");
                
                // 建立 EnvelopedCms 物件
                ContentInfo contentInfo = new ContentInfo(fileContent);
                EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);
                
                // 為收件者加密
                CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, certificate);
                envelopedCms.Encrypt(recipient);
                
                // 取得加密後的內容
                byte[] encryptedData = envelopedCms.Encode();
                
                // 儲存加密後的檔案
                string outputPath = filePath + ".cms";
                File.WriteAllBytes(outputPath, encryptedData);
                Console.WriteLine($"已加密檔案: {outputPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"加密失敗: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"詳細錯誤: {ex.InnerException.Message}");
                }
            }
        }

        private static void DecryptFile(string filePath)
        {
            if (!filePath.EndsWith(".p7m") && !filePath.EndsWith(".pgp") && !filePath.EndsWith(".cms"))
            {
                throw new Exception("請提供有效的加密檔案 (.p7m, .cms 或 .pgp)");
            }

            byte[] encryptedData;
            
            if (filePath.EndsWith(".pgp"))
            {
                // 處理ASCII編碼加密檔 (OpenPGP格式)
                string asciiContent = File.ReadAllText(filePath);
                
                // 提取Base64內容
                int startIdx = asciiContent.IndexOf("-----BEGIN PGP MESSAGE-----");
                int endIdx = asciiContent.IndexOf("-----END PGP MESSAGE-----");
                
                if (startIdx < 0 || endIdx < 0)
                {
                    throw new Exception("無效的OpenPGP加密檔案格式");
                }
                
                // 跳過頭部 - 找到第一個空行後的內容
                startIdx = asciiContent.IndexOf("\n\n", startIdx);
                if (startIdx < 0)
                {
                    startIdx = asciiContent.IndexOf("\r\n\r\n", startIdx);
                }
                
                if (startIdx < 0)
                {
                    throw new Exception("無效的OpenPGP加密檔案格式 - 找不到頭部結束");
                }
                
                startIdx += 2;  // 跳過空行
                
                // 提取內容直到"="字符（CRC校驗和行的開始）
                int crcIdx = asciiContent.LastIndexOf('=', endIdx);
                if (crcIdx < 0)
                {
                    crcIdx = endIdx;
                }
                
                // 提取Base64編碼的加密數據
                string base64Content = asciiContent.Substring(startIdx, crcIdx - startIdx);
                
                // 移除所有換行符
                base64Content = base64Content.Replace("\r", "").Replace("\n", "");
                
                try
                {
                    // 轉換為二進制
                    encryptedData = Convert.FromBase64String(base64Content);
                }
                catch (Exception ex)
                {
                    throw new Exception($"無法解碼Base64加密數據: {ex.Message}");
                }
            }
            else
            {
                // 處理二進制加密檔 (.p7m 或 .cms)
                encryptedData = File.ReadAllBytes(filePath);
            }

            try
            {
                // 使用X509證書存放區中的私鑰解密
                EnvelopedCms envelopedCms = new EnvelopedCms();
                envelopedCms.Decode(encryptedData);
                
                // 嘗試解密
                envelopedCms.Decrypt();
                
                // 提取原始內容
                byte[] decryptedContent = envelopedCms.ContentInfo.Content;
                string outputPath = filePath.Replace(".p7m", "").Replace(".pgp", "").Replace(".cms", "") + ".decrypted";
                File.WriteAllBytes(outputPath, decryptedContent);
                
                Console.WriteLine($"檔案解密成功: {outputPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"檔案解密失敗: {ex.Message}");
            }
        }

        private static X509Certificate2 FindCertificateDirectly(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                return null;
            }

            Console.WriteLine($"直接尋找證書: {identifier}");

            // 嘗試從個人存放區尋找證書
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                // 處理SHA1指紋 (不區分大小寫並移除空格和冒號)
                string cleanIdentifier = identifier.Replace(" ", "").Replace(":", "").Replace("-", "").ToLowerInvariant();
                Console.WriteLine($"清理後的識別碼: {cleanIdentifier}");

                // 僅尋找完全匹配的證書指紋，若找不到則返回null
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        string thumbprint = cert.Thumbprint.Replace(" ", "").Replace(":", "").Replace("-", "").ToLowerInvariant();
                        
                        if (string.Equals(thumbprint, cleanIdentifier, StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("找到完全匹配的SHA1指紋證書!");
                            return new X509Certificate2(cert);
                        }
                    }
                }
            }

            // 如果找不到匹配的證書指紋，返回null
            return null;
        }

        // 創建雜湊演算法，避免使用已淘汰的HashAlgorithm.Create(string)方法
        private static HashAlgorithm CreateHashAlgorithm(string algorithm)
        {
            switch (algorithm.ToUpper())
            {
                case "SHA1":
                    return System.Security.Cryptography.SHA1.Create();
                case "SHA256":
                    return System.Security.Cryptography.SHA256.Create();
                case "SHA384":
                    return System.Security.Cryptography.SHA384.Create();
                case "SHA512":
                    return System.Security.Cryptography.SHA512.Create();
                default:
                    return System.Security.Cryptography.SHA384.Create(); // 預設使用SHA384
            }
        }

        // 獲取雜湊演算法的OID
        private static string GetHashAlgorithmOid(string algorithm)
        {
            switch (algorithm.ToUpper())
            {
                case "SHA1":
                    return "1.3.14.3.2.26";
                case "SHA256":
                    return "2.16.840.1.101.3.4.2.1";
                case "SHA384":
                    return "2.16.840.1.101.3.4.2.2";
                case "SHA512":
                    return "2.16.840.1.101.3.4.2.3";
                default:
                    return "2.16.840.1.101.3.4.2.2"; // SHA384
            }
        }
    }
} 