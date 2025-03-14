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
using System.Reflection;

namespace SmartFileCrypto
{
    public class Program
    {
        // 增加全域變數來控制詳細輸出
        private static bool _debugMode = false;
        
        static async Task Main(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    PrintUsage();
                    return;
                }

                string command = args[0].ToLower();
                
                // 檢查全域調試模式
                for (int i = 1; i < args.Length; i++)
                {
                    if (args[i].ToLower() == "--debug" || args[i].ToLower() == "--verbose")
                    {
                        _debugMode = true;
                        Console.WriteLine("已啟用調試模式，將顯示詳細訊息");
                        break;
                    }
                }
                
                // 顯示版本資訊
                Console.WriteLine($"SmartFileCrypto - 檔案加密與簽章工具 v{Assembly.GetExecutingAssembly().GetName().Version}");
                Console.WriteLine();
                
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
                        
                        // 檢查檔案是否存在
                        if (!File.Exists(verifyFilePath))
                        {
                            Console.WriteLine($"錯誤: 找不到檔案 '{verifyFilePath}'");
                            return;
                        }
                        
                        // 檢查是否要提取內容
                        bool extractContent = false;
                        for (int i = 1; i < args.Length; i++)
                        {
                            if (args[i].ToLower() == "--extract-content")
                            {
                                extractContent = true;
                                break;
                            }
                        }
                        
                        VerifySignature(verifyFilePath, extractContent);
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
                        
                        // 檢查檔案是否存在
                        if (!File.Exists(decryptFilePath))
                        {
                            Console.WriteLine($"錯誤: 找不到檔案 '{decryptFilePath}'");
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
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"權限錯誤: {ex.Message}");
                Console.WriteLine("請確保您有足夠的權限存取檔案和憑證。");
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                Console.WriteLine($"加密操作錯誤: {ex.Message}");
                Console.WriteLine("可能是憑證問題或加密操作失敗，請檢查憑證狀態和有效性。");
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine($"檔案不存在: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"操作失敗: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"詳細錯誤: {ex.InnerException.Message}");
                }
                
                if (_debugMode)
                {
                    Console.WriteLine("完整錯誤堆疊:");
                    Console.WriteLine(ex.ToString());
                }
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("SmartFileCrypto - 檔案加密與簽章工具");
            Console.WriteLine();
            Console.WriteLine("使用方式:");
            Console.WriteLine("  SmartFileCrypto <命令> [選項] <檔案路徑>");
            Console.WriteLine();
            Console.WriteLine("可用命令:");
            Console.WriteLine("  sign       使用憑證簽署檔案");
            Console.WriteLine("  verify     驗證已簽章檔案");
            Console.WriteLine("  encrypt    使用憑證加密檔案");
            Console.WriteLine("  decrypt    使用憑證解密檔案");
            Console.WriteLine("  list-certs 列出可用的憑證");
            Console.WriteLine();
            Console.WriteLine("常用選項:");
            Console.WriteLine("  --cert=<識別碼>      指定要使用的憑證，可以是主題名稱的一部分或序號");
            Console.WriteLine("  --sha1=<指紋>        使用SHA1指紋直接選擇憑證");
            Console.WriteLine("  --cert-file=<路徑>   使用憑證檔案進行加密 (僅適用於加密，支援 .cer, .crt, .pem 格式)");
            Console.WriteLine("  --hash=<算法>        指定雜湊演算法 (SHA1, SHA256, SHA384, SHA512)，預設為SHA384");
            Console.WriteLine("  --timestamp          新增時間戳記 (預設使用 DigiCert 時間戳記伺服器)");
            Console.WriteLine("  --timestamp=<URL>    指定自訂時間戳記伺服器URL");
            Console.WriteLine("  --include-content    在簽章中包含原始內容 (不使用分離式簽章)");
            Console.WriteLine("  --extract-content    從簽章中提取原始內容 (僅適用於驗證)");
            Console.WriteLine("  --debug              顯示詳細的診斷訊息");
            Console.WriteLine();
            Console.WriteLine("備註:");
            Console.WriteLine("  * 如未指定憑證，系統會顯示憑證選擇對話框");
            Console.WriteLine("  * 簽章檔案將使用 .p7s 副檔名");
            Console.WriteLine("  * 簽章預設不包含原始檔案內容 (分離式簽章)");
            Console.WriteLine("  * 加密後的檔案將使用 .cms 副檔名");
            Console.WriteLine();
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
                        bool hasSignatureCapability = false;
                        
                        // 檢查金鑰使用擴展
                        foreach (X509Extension ext in cert.Extensions)
                        {
                            if (ext is X509KeyUsageExtension keyUsage)
                            {
                                // 檢查數位簽章或不可否認性標誌，兩者都可用於簽名
                                if ((keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == X509KeyUsageFlags.DigitalSignature ||
                                    (keyUsage.KeyUsages & X509KeyUsageFlags.NonRepudiation) == X509KeyUsageFlags.NonRepudiation)
                                {
                                    hasSignatureCapability = true;
                                    break;
                                }
                            }
                            
                            // 檢查擴展金鑰使用擴展
                            if (ext is X509EnhancedKeyUsageExtension enhancedKeyUsage)
                            {
                                foreach (var oid in enhancedKeyUsage.EnhancedKeyUsages)
                                {
                                    // 檢查是否包含代碼簽章、文件簽章或其他簽名相關的OID
                                    if (oid.Value == "1.3.6.1.5.5.7.3.3" || // Code Signing
                                        oid.Value == "1.3.6.1.4.1.311.10.3.12" || // Document Signing
                                        oid.Value == "1.2.840.113583.1.1.5") // Adobe PDF Signing
                                    {
                                        hasSignatureCapability = true;
                                        break;
                                    }
                                }
                                
                                if (hasSignatureCapability)
                                {
                                    break;
                                }
                            }
                        }
                        
                        // 如果金鑰使用沒有明確禁止簽章，且憑證具有私鑰，也視為可用於簽章
                        if (!hasSignatureCapability)
                        {
                            bool hasExplicitlyDisabledSignature = false;
                            foreach (X509Extension ext in cert.Extensions)
                            {
                                if (ext is X509KeyUsageExtension keyUsage)
                                {
                                    // 如果有明確設定且排除了數位簽章和不可否認性，則視為不可用於簽章
                                    if ((keyUsage.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) == 0)
                                    {
                                        hasExplicitlyDisabledSignature = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (!hasExplicitlyDisabledSignature)
                            {
                                hasSignatureCapability = true;
                            }
                        }
                        
                        if (hasSignatureCapability)
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
                    // 憑證篩選條件：可用於加密
                    // 檢查是否包含公鑰和加密用途
                    foreach (X509Certificate2 cert in collection)
                    {
                        bool canBeUsedForEncryption = false;
                        
                        // 檢查公鑰是否存在
                        if (cert.PublicKey != null && 
                            (cert.GetRSAPublicKey() != null || 
                             cert.GetECDiffieHellmanPublicKey() != null))
                        {
                            // 檢查金鑰使用擴展
                            bool hasKeyUsageRestriction = false;
                            
                            foreach (X509Extension ext in cert.Extensions)
                            {
                                if (ext is X509KeyUsageExtension keyUsage)
                                {
                                    hasKeyUsageRestriction = true;
                                    
                                    // 檢查金鑰加密標誌
                                    if ((keyUsage.KeyUsages & X509KeyUsageFlags.KeyEncipherment) == X509KeyUsageFlags.KeyEncipherment ||
                                        (keyUsage.KeyUsages & X509KeyUsageFlags.DataEncipherment) == X509KeyUsageFlags.DataEncipherment)
                                    {
                                        canBeUsedForEncryption = true;
                                        break;
                                    }
                                }
                            }
                            
                            // 如果沒有明確的金鑰使用限制，則假設可以用於加密
                            if (!hasKeyUsageRestriction)
                            {
                                canBeUsedForEncryption = true;
                            }
                        }
                        
                        if (canBeUsedForEncryption)
                        {
                            filteredCollection.Add(cert);
                        }
                    }
                    
                    // 如果沒有符合條件的證書，顯示錯誤訊息
                    if (filteredCollection.Count == 0)
                    {
                        throw new Exception("找不到任何可用於加密的憑證。");
                    }
                }
                else
                {
                    // 若沒有特定操作，顯示所有證書
                    filteredCollection = collection;
                }

                // 設定對話框標題和提示訊息
                string dialogTitle = "選擇憑證";
                string dialogMessage = "請選擇要使用的憑證";
                
                if (operation == "sign")
                {
                    dialogTitle = "選擇簽署憑證";
                    dialogMessage = "請選擇要用於簽署文件的憑證 (僅顯示具有數位簽章或不可否認能力的憑證)";
                }
                else if (operation == "encrypt")
                {
                    dialogTitle = "選擇加密憑證";
                    dialogMessage = "請選擇要用於加密文件的憑證 (顯示所有具有公鑰的憑證)";
                }

                // 使用X509Certificate2UI類別從正確的命名空間
                X509Certificate2Collection selected = X509Certificate2UI.SelectFromCollection(
                    filteredCollection,
                    dialogTitle,
                    dialogMessage,
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
            bool includeContent = false; // 預設不包含內容
            
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
                else if (arg == "--include-content")
                {
                    includeContent = true;
                }
            }
            
            // 簽署檔案
            await SignFile(filePath, certIdentifier, useTimestamp, tsaUrl, hashAlgorithm, includeContent);
        }
        
        private static async Task HandleEncryptCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("錯誤: 加密命令需要指定檔案路徑");
                PrintUsage();
                return;
            }
            
            // 找出檔案路徑（第一個非參數選項）
            string filePath = FindFilePath(args, 1);
            if (filePath == null)
            {
                Console.WriteLine("錯誤: 未指定有效的檔案路徑");
                PrintUsage();
                return;
            }
            
            // 檢查檔案是否存在
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"錯誤: 找不到檔案 '{filePath}'");
                return;
            }
            
            string certIdentifier = null;
            string certFilePath = null;
            
            // 處理參數
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i].StartsWith("--cert="))
                {
                    certIdentifier = args[i].Substring("--cert=".Length);
                }
                else if (args[i].StartsWith("--sha1="))
                {
                    certIdentifier = args[i].Substring("--sha1=".Length);
                }
                else if (args[i].StartsWith("--cert-file="))
                {
                    certFilePath = args[i].Substring("--cert-file=".Length);
                }
            }
            
            // 使用憑證檔案加密
            if (!string.IsNullOrEmpty(certFilePath))
            {
                EncryptFileWithCertFile(filePath, certFilePath);
                return;
            }
            
            // 使用憑證加密
            EncryptFile(filePath, certIdentifier);
        }
        
        // 新增輔助方法來在參數列表中尋找檔案路徑
        private static string FindFilePath(string[] args, int startIndex)
        {
            // 尋找第一個不是參數的參數（即不是以--開頭）
            for (int i = startIndex; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--"))
                {
                    // 進行安全性檢查
                    string path = args[i];
                    
                    // 檢查路徑是否有效
                    if (string.IsNullOrWhiteSpace(path))
                    {
                        Console.WriteLine("錯誤: 指定的檔案路徑無效");
                        return null;
                    }
                    
                    // 檢查路徑是否包含不允許的字符
                    char[] invalidChars = Path.GetInvalidPathChars();
                    if (path.IndexOfAny(invalidChars) >= 0)
                    {
                        Console.WriteLine("錯誤: 檔案路徑包含無效字符");
                        return null;
                    }
                    
                    // 檢查是否為絕對路徑或相對路徑
                    if (!Path.IsPathRooted(path))
                    {
                        path = Path.GetFullPath(path);
                    }
                    
                    return path;
                }
            }
            
            return null;
        }

        private static async Task SignFile(string filePath, string certIdentifier, bool useTimestamp, string tsaUrl, string hashAlgorithm, bool includeContent)
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
                Console.WriteLine($"包含檔案內容: {(includeContent ? "是" : "否")}");
                
                // 建立CMS簽名
                ContentInfo contentInfo = new ContentInfo(fileContent);
                SignedCms signedCms = new SignedCms(contentInfo, !includeContent); // detached = !includeContent
                
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
                
                // 根據是否包含內容決定儲存的副檔名
                string extension = includeContent ? ".p7m" : ".p7s";
                string outputPath = filePath + extension;
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
                        Console.WriteLine($"時間戳記時間 (UTC): {timestampTime.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC");
                        Console.WriteLine($"時間戳記時間 (本地): {timestampTime.ToLocalTime():yyyy-MM-dd HH:mm:ss} {TimeZoneInfo.Local.DisplayName}");

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

        private static void VerifySignature(string filePath, bool extractContent = false)
        {
            try
            {
                // 檢查檔案副檔名，判斷類型
                bool isP7mFile = filePath.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase);
                bool isP7sFile = filePath.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase);
                
                if (!isP7mFile && !isP7sFile)
                {
                    Console.WriteLine($"警告: 檔案 '{filePath}' 沒有標準的簽章副檔名 (.p7s 或 .p7m)");
                }
                
                // 讀取簽章檔案內容
                byte[] signatureBytes = File.ReadAllBytes(filePath);
                Console.WriteLine($"已讀取二進制檔案 ({signatureBytes.Length} 字節)");
                
                // 檢查對應的原始檔案是否存在
                string originalFilePath = null;
                if (isP7sFile)
                {
                    // 對於.p7s檔案，原始檔案應該是去掉.p7s的檔案
                    originalFilePath = filePath.Substring(0, filePath.Length - 4);
                }
                else if (isP7mFile)
                {
                    // 對於.p7m檔案，首先要判斷它是加密檔案還是包含內容的簽章
                    try
                    {
                        // 嘗試當作EnvelopedCms解碼
                        EnvelopedCms envelopedCms = new EnvelopedCms();
                        envelopedCms.Decode(signatureBytes);
                        
                        // 如果解碼成功但沒有拋出異常，則可能是加密檔案而非簽章
                        Console.WriteLine("錯誤: 指定的檔案似乎是加密檔案 (.p7m)，而非簽章檔案 (.p7s)");
                        Console.WriteLine("請使用 'decrypt' 命令來解密該檔案，或檢查您是否提供了正確的檔案");
                        return;
                    }
                    catch
                    {
                        // 如果EnvelopedCms解碼失敗，可能是非分離式簽章
                        try
                        {
                            SignedCms checkCms = new SignedCms();
                            checkCms.Decode(signatureBytes);
                            
                            // 檢查是否包含內容
                            bool hasContent = checkCms.ContentInfo.Content != null && checkCms.ContentInfo.Content.Length > 0;
                            if (hasContent)
                            {
                                Console.WriteLine("檔案包含內容的非分離式簽章 (.p7m)");
                                // 不需要原始檔案，因為內容包含在簽章中
                                originalFilePath = null;
                            }
                            else
                            {
                                // 可能是分離式簽章但使用了.p7m副檔名
                                originalFilePath = filePath.Substring(0, filePath.Length - 4);
                                Console.WriteLine($"警告: 檔案使用了.p7m副檔名但似乎是分離式簽章，嘗試使用原始檔案: {originalFilePath}");
                            }
                        }
                        catch
                        {
                            // 如果SignedCms解碼也失敗，則可能是無效或損壞的檔案
                            Console.WriteLine("錯誤: 無法解析檔案格式，既不是有效的加密檔案也不是有效的簽章檔案");
                            return;
                        }
                    }
                }
                
                // 檢查對應的原始檔案是否存在
                if (originalFilePath != null)
                {
                    if (!File.Exists(originalFilePath))
                    {
                        Console.WriteLine($"警告: 找不到原始檔案 '{originalFilePath}' ，將嘗試直接解析簽名");
                    }
                    else
                    {
                        Console.WriteLine($"已找到原始檔案: {originalFilePath}");
                    }
                }
                
                // 準備解碼簽章
                SignedCms signedCms = new SignedCms();
                bool hasEmbeddedContent = false;
                bool verificationSucceeded = false;
                bool fileMatchesSignature = false; // 新增標記，表示檔案內容是否與簽章匹配
                
                if (_debugMode)
                {
                    Console.WriteLine("正在驗證簽章...");
                }
                
                // 多種驗證嘗試
                // 首先，嘗試非分離式簽章解碼
                try
                {
                    DebugLog("嘗試非分離式簽章解碼...");
                    signedCms.Decode(signatureBytes);
                    
                    // 檢查是否包含內容
                    hasEmbeddedContent = signedCms.ContentInfo.Content != null && signedCms.ContentInfo.Content.Length > 0;
                    
                    if (hasEmbeddedContent)
                    {
                        try
                        {
                            // 嘗試直接驗證包含內容的簽章
                            signedCms.CheckSignature(true);
                            verificationSucceeded = true;
                            fileMatchesSignature = true;
                            Console.WriteLine("非分離式簽章驗證成功");
                        }
                        catch (Exception ex)
                        {
                            DebugLog($"非分離式簽章驗證失敗: {ex.Message}");
                            
                            // 嘗試寬容模式
                            try
                            {
                                signedCms.CheckSignature(false);
                                // 寬容模式成功，但我們不將其視為完全驗證成功
                                DebugLog("寬容模式驗證部分成功，檔案內容可能已被修改");
                            }
                            catch
                            {
                                DebugLog("寬容模式驗證也失敗");
                            }
                        }
                    }
                    else if (originalFilePath != null && File.Exists(originalFilePath))
                    {
                        // 如果簽章不包含內容但找到了原始檔案，嘗試分離式簽章驗證
                        byte[] contentBytes = File.ReadAllBytes(originalFilePath);
                        
                        try
                        {
                            // 方法 1: 標準分離式簽名 (重新創建SignedCms)
                            DebugLog("嘗試標準分離式簽名驗證方法...");
                            ContentInfo contentInfo = new ContentInfo(contentBytes);
                            SignedCms standardCms = new SignedCms(contentInfo, true); // detached = true
                            standardCms.Decode(signatureBytes);
                            
                            try
                            {
                                standardCms.CheckSignature(true);
                                signedCms = standardCms;
                                verificationSucceeded = true;
                                fileMatchesSignature = true;
                                Console.WriteLine("使用標準分離式簽名方法驗證成功");
                            }
                            catch (Exception standardEx)
                            {
                                DebugLog($"標準簽名檢查失敗: {standardEx.Message}");
                                
                                // 嘗試寬容檢查
                                try
                                {
                                    standardCms.CheckSignature(false);
                                    signedCms = standardCms;
                                    // 寬容模式成功，但我們不將其視為完全驗證成功
                                    DebugLog("寬容模式驗證部分成功，檔案內容可能已被修改");
                                }
                                catch
                                {
                                    DebugLog("寬容模式驗證也失敗");
                                }
                            }
                        }
                        catch (Exception ex1)
                        {
                            DebugLog($"標準分離式簽名驗證失敗: {ex1.Message}");
                            
                            // 方法 2: 嘗試反射方式設置內容
                            try
                            {
                                DebugLog("嘗試使用反射方式設置內容...");
                                PrivateSetContentMethod(signedCms, contentBytes);
                                
                                try
                                {
                                    signedCms.CheckSignature(true);
                                    verificationSucceeded = true;
                                    fileMatchesSignature = true;
                                    Console.WriteLine("使用反射設置內容方法驗證成功");
                                }
                                catch (Exception reflectEx)
                                {
                                    DebugLog($"反射設置內容驗證失敗: {reflectEx.Message}");
                                }
                            }
                            catch (Exception ex2)
                            {
                                DebugLog($"反射設置內容方法失敗: {ex2.Message}");
                            }
                        }
                    }
                }
                catch (Exception decodeEx)
                {
                    DebugLog($"簽章解碼失敗: {decodeEx.Message}");
                    Console.WriteLine("無法解析簽章數據，檔案可能不是有效的簽章檔案");
                    return;
                }
                
                // 檢查signedCms是否已初始化且有簽名者信息
                if (signedCms.SignerInfos.Count > 0)
                {
                    // 更新hasEmbeddedContent標記
                    hasEmbeddedContent = signedCms.ContentInfo.Content != null && signedCms.ContentInfo.Content.Length > 0;
                    Console.WriteLine($"簽章包含檔案內容: {(hasEmbeddedContent ? "是" : "否")}");
                    
                    // 如果要求提取內容且簽章包含內容
                    if (extractContent && hasEmbeddedContent)
                    {
                        byte[] content = signedCms.ContentInfo.Content;
                        ExtractContentToFile(content, filePath);
                    }
                    
                    // 顯示簽章信息
                    DisplaySignatureInfo(signedCms);
                    
                    // 根據驗證結果顯示相應訊息
                    if (verificationSucceeded && fileMatchesSignature)
                    {
                        Console.WriteLine("簽章驗證成功!");
                    }
                    else
                    {
                        Console.WriteLine("簽章驗證失敗");
                        // 提供更具體的錯誤原因
                        if (signedCms.SignerInfos.Count > 0 && signedCms.SignerInfos[0].Certificate != null)
                        {
                            Console.WriteLine("可能原因: 檔案內容與簽章不匹配或簽章已損壞");
                        }
                        
                        if (!_debugMode)
                        {
                            Console.WriteLine("如需查看詳細錯誤診斷，請使用 --debug 參數");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("簽章不包含任何簽名者信息");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"處理簽章時發生錯誤: {ex.Message}");
                if (ex.InnerException != null && _debugMode)
                {
                    Console.WriteLine($"內部錯誤: {ex.InnerException.Message}");
                }
            }
        }
        
        // 輔助方法：提取內容到檔案
        private static void ExtractContentToFile(byte[] content, string signatureFilePath)
        {
            try
            {
                // 生成輸出檔案名稱，移除副檔名
                string outputFileName = null;
                
                if (signatureFilePath.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase))
                {
                    outputFileName = signatureFilePath.Substring(0, signatureFilePath.Length - 4) + ".extracted";
                }
                else if (signatureFilePath.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase))
                {
                    outputFileName = signatureFilePath.Substring(0, signatureFilePath.Length - 4) + ".extracted";
                }
                else
                {
                    outputFileName = signatureFilePath + ".extracted";
                }
                
                // 檢查輸出路徑是否與原始檔案相同
                string originalFilePath = signatureFilePath;
                if (signatureFilePath.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase) ||
                    signatureFilePath.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase))
                {
                    originalFilePath = signatureFilePath.Substring(0, signatureFilePath.Length - 4);
                }
                
                // 如果原始檔案存在，檢查內容是否相同
                if (File.Exists(originalFilePath))
                {
                    try
                    {
                        byte[] originalContent = File.ReadAllBytes(originalFilePath);
                        if (content.SequenceEqual(originalContent))
                        {
                            Console.WriteLine($"提取的內容與原始檔案 '{originalFilePath}' 內容完全一致，無需另存");
                            return; // 不需要保存相同的內容
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"比較檔案內容時出錯: {ex.Message}");
                    }
                }
                
                // 寫入檔案前檢查是否檔案已存在
                if (File.Exists(outputFileName))
                {
                    Console.WriteLine($"輸出檔案 '{outputFileName}' 已存在，將覆蓋");
                }
                
                // 寫入檔案
                File.WriteAllBytes(outputFileName, content);
                Console.WriteLine($"已提取簽章內容至檔案: {outputFileName}");
                
                // 嘗試判斷檔案類型
                TryDetermineFileType(outputFileName, content);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"提取內容到檔案時發生錯誤: {ex.Message}");
            }
        }
        
        // 嘗試判斷檔案類型
        private static void TryDetermineFileType(string outputFileName, byte[] content)
        {
            try
            {
                // 檢查檔案頭部特徵以判斷檔案類型
                if (content.Length < 8) return; // 太小的檔案無法判斷
                
                // 文字檔案特徵
                bool isTextFile = true;
                foreach (byte b in content.Take(Math.Min(content.Length, 1024)))
                {
                    // 檢查非ASCII和控制字符
                    if ((b < 32 || b > 126) && b != 9 && b != 10 && b != 13)
                    {
                        isTextFile = false;
                        break;
                    }
                }
                
                if (isTextFile)
                {
                    Console.WriteLine("提取的內容可能是文字檔案");
                    return;
                }
                
                // 常見檔案類型特徵
                if (content[0] == 0x25 && content[1] == 0x50 && content[2] == 0x44 && content[3] == 0x46) // %PDF
                {
                    Console.WriteLine("提取的內容為PDF檔案");
                }
                else if (content[0] == 0x50 && content[1] == 0x4B && content[2] == 0x03 && content[3] == 0x04) // PK..
                {
                    Console.WriteLine("提取的內容可能是ZIP/Office檔案");
                }
                else if (content[0] == 0xFF && content[1] == 0xD8 && content[2] == 0xFF) // JPEG
                {
                    Console.WriteLine("提取的內容為JPEG圖片");
                }
                else if (content[0] == 0x89 && content[1] == 0x50 && content[2] == 0x4E && content[3] == 0x47) // .PNG
                {
                    Console.WriteLine("提取的內容為PNG圖片");
                }
                else if (content[0] == 0x47 && content[1] == 0x49 && content[2] == 0x46 && content[3] == 0x38) // GIF8
                {
                    Console.WriteLine("提取的內容為GIF圖片");
                }
                else
                {
                    Console.WriteLine("檔案類型判斷: 未知或二進制檔案");
                }
            }
            catch (Exception ex)
            {
                DebugLog($"判斷檔案類型時出錯: {ex.Message}");
            }
        }
        
        // 輔助方法：嘗試將內容顯示為文字（保留但重定向到新方法）
        private static void TryDisplayContent(byte[] content)
        {
            // 此方法不再用於顯示內容，而是重定向到提取內容的方法
            // 使用臨時檔案名，實際上在此方法調用中沒有使用該參數
            ExtractContentToFile(content, "content");
        }
        
        // 輔助方法：顯示簽章信息
        private static void DisplaySignatureInfo(SignedCms signedCms)
        {
                    if (signedCms.SignerInfos.Count > 0)
                    {
                        SignerInfo signer = signedCms.SignerInfos[0];
                        X509Certificate2 signerCert = signer.Certificate;
                        
                        if (signerCert != null)
                        {
                            Console.WriteLine($"簽署者: {signerCert.Subject}");
                            Console.WriteLine($"證書指紋: {BitConverter.ToString(signerCert.GetCertHash()).Replace("-", "")}");
                    Console.WriteLine($"證書有效期: {signerCert.NotBefore.ToLocalTime():yyyy-MM-dd HH:mm:ss} 至 {signerCert.NotAfter.ToLocalTime():yyyy-MM-dd HH:mm:ss} ({TimeZoneInfo.Local.DisplayName})");
                        }
                
                // 顯示使用的雜湊演算法
                string digestAlgorithm = GetFriendlyAlgorithmName(signer.DigestAlgorithm);
                Console.WriteLine($"雜湊演算法: {digestAlgorithm}");
                        
                        // 檢查時間戳記
                        DateTime? signingTime = GetSigningTime(signer);
                        if (signingTime.HasValue)
                        {
                    Console.WriteLine($"簽署時間 (UTC): {signingTime.Value.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC");
                    Console.WriteLine($"簽署時間 (本地): {signingTime.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss} {TimeZoneInfo.Local.DisplayName}");
                }
                
                // 檢查時間戳記
                DisplayTimestampInfo(signer);
            }
        }

        // 輔助方法：根據OID獲取友好的演算法名稱
        private static string GetFriendlyAlgorithmName(Oid digestAlgorithm)
        {
            if (digestAlgorithm == null)
                return "Unknown";
                
            switch (digestAlgorithm.Value)
            {
                case "1.3.14.3.2.26":
                    return "SHA1";
                case "2.16.840.1.101.3.4.2.1":
                    return "SHA256";
                case "2.16.840.1.101.3.4.2.2":
                    return "SHA384";
                case "2.16.840.1.101.3.4.2.3":
                    return "SHA512";
                case "1.2.840.113549.1.1.4":
                    return "MD5";
                case "1.2.840.113549.1.1.5":
                    return "SHA1 with RSA";
                case "1.2.840.113549.1.1.11":
                    return "SHA256 with RSA";
                case "1.2.840.113549.1.1.12":
                    return "SHA384 with RSA";
                case "1.2.840.113549.1.1.13":
                    return "SHA512 with RSA";
                case "1.2.840.10045.4.1":
                    return "SHA1 with ECDSA";
                case "1.2.840.10045.4.3.2":
                    return "SHA256 with ECDSA";
                case "1.2.840.10045.4.3.3":
                    return "SHA384 with ECDSA";
                case "1.2.840.10045.4.3.4":
                    return "SHA512 with ECDSA";
                default:
                    return $"{digestAlgorithm.FriendlyName ?? "Unknown"} ({digestAlgorithm.Value})";
            }
        }
        
        // 輔助方法：顯示時間戳記信息
        private static void DisplayTimestampInfo(SignerInfo signer)
        {
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
                        Console.WriteLine($"時間戳記時間 (UTC): {info.GenTime.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC");
                        Console.WriteLine($"時間戳記時間 (本地): {info.GenTime.ToLocalTime():yyyy-MM-dd HH:mm:ss} {TimeZoneInfo.Local.DisplayName}");
                                    Console.WriteLine($"時間戳記序號: {info.SerialNumber}");
                                    
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
                                        DateTime timeStampDateTime = timeValue.ToDateTime();
                                        Console.WriteLine($"時間戳記時間 (UTC): {timeStampDateTime.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC");
                                        Console.WriteLine($"時間戳記時間 (本地): {timeStampDateTime.ToLocalTime():yyyy-MM-dd HH:mm:ss} {TimeZoneInfo.Local.DisplayName}");
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
                    
        // 嘗試使用反射設置 SignedCms 的內容（用於相容性）
        private static void PrivateSetContentMethod(SignedCms cms, byte[] content)
        {
            try
            {
                // 首先嘗試直接生成一個新的ContentInfo
                ContentInfo contentInfo = new ContentInfo(content);
                
                // 取得SignedCms的類型
                Type cmsType = cms.GetType();
                
                // 嘗試方法1：反射找到_contentInfo字段並設置
                try
                {
                    FieldInfo contentInfoField = cmsType.GetField("_contentInfo", BindingFlags.NonPublic | BindingFlags.Instance);
                    if (contentInfoField != null)
                    {
                        contentInfoField.SetValue(cms, contentInfo);
                        DebugLog("通過反射設置_contentInfo字段成功");
                        return;
                    }
                }
                catch (Exception reflectEx)
                {
                    DebugLog($"反射設置_contentInfo字段失敗: {reflectEx.Message}");
                }
                
                // 嘗試方法2：查找任何可能的set_ContentInfo方法
                try
                {
                    var methods = cmsType.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Public);
                    
                    foreach (var method in methods)
                    {
                        if (method.Name.Contains("ContentInfo") && method.Name.StartsWith("set_"))
                        {
                            try
                            {
                                method.Invoke(cms, new object[] { contentInfo });
                                Console.WriteLine($"通過反射調用{method.Name}方法成功");
                                return;
                            }
                            catch
                            {
                                // 忽略方法調用失敗，繼續嘗試下一個方法
                            }
                        }
                    }
                }
                catch (Exception methodEx)
                {
                    DebugLog($"反射調用set_ContentInfo方法失敗: {methodEx.Message}");
                }
                
                // 獲取所有字段用於後續嘗試
                var allFields = cmsType.GetFields(BindingFlags.NonPublic | BindingFlags.Instance);
                
                // 嘗試方法3：尋找名稱包含Content的字段
                try
                {
                    foreach (var field in allFields)
                    {
                        if (field.Name.Contains("content") || field.Name.Contains("Content"))
                        {
                            try
                            {
                                // 對於ContentInfo類型的字段
                                if (field.FieldType == typeof(ContentInfo))
                                {
                                    field.SetValue(cms, contentInfo);
                                    DebugLog($"通過字段{field.Name}設置內容成功");
                                    return;
                                }
                                // 對於byte[]類型的字段
                                else if (field.FieldType == typeof(byte[]))
                                {
                                    field.SetValue(cms, content);
                                    DebugLog($"通過字段{field.Name}設置內容byte[]成功");
                                    return;
                                }
                            }
                            catch
                            {
                                // 忽略字段設置失敗，繼續嘗試下一個字段
                            }
                        }
                    }
                }
                catch (Exception fieldEx)
                {
                    DebugLog($"反射設置內容字段失敗: {fieldEx.Message}");
                }
                
                // 嘗試方法4：使用新的SignedCms對象替換
                try
                {
                    // 創建一個新的SignedCms對象，使用原始簽名的編碼數據
                    byte[] encodedData = cms.Encode();
                    SignedCms newCms = new SignedCms(contentInfo, false);
                    newCms.Decode(encodedData);
                    
                    // 嘗試將新對象的屬性複製回原始對象
                    foreach (var field in allFields)
                    {
                        try
                        {
                            var value = field.GetValue(newCms);
                            field.SetValue(cms, value);
                        }
                        catch
                        {
                            // 忽略屬性複製失敗
                        }
                    }
                    
                    DebugLog("通過創建新對象並複製屬性設置內容成功");
                }
                catch (Exception newCmsEx)
                {
                    DebugLog($"通過新對象設置內容失敗: {newCmsEx.Message}");
                }
                
                DebugLog("警告：所有嘗試設置內容的方法都失敗，將繼續使用原始簽名");
            }
            catch (Exception ex)
            {
                DebugLog($"嘗試設置內容時發生錯誤: {ex.Message}");
            }
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
                
                // 儲存加密後的檔案，統一使用 .cms 副檔名
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
            // 基於副檔名判斷文件類型
            bool isCertificateEncrypted = filePath.EndsWith(".p7m") || filePath.EndsWith(".cms") || filePath.EndsWith(".pgp");
            
            if (!isCertificateEncrypted)
            {
                throw new Exception("請提供有效的加密檔案 (.p7m, .cms, .pgp)");
            }
            
            // 使用憑證解密
            DecryptFileWithCertificate(filePath);
        }

        private static void DecryptFileWithCertificate(string filePath)
        {
            try
            {
                // 讀取加密檔案
                byte[] encryptedData = File.ReadAllBytes(filePath);
                
                // 建立 EnvelopedCms 物件
                EnvelopedCms envelopedCms = new EnvelopedCms();
                
                try
                {
                    // 嘗試解碼加密資料
                    envelopedCms.Decode(encryptedData);
                }
                catch (CryptographicException ex)
                {
                    // 如果解碼失敗，可能不是有效的 CMS 格式
                    throw new Exception($"無法解碼加密資料: {ex.Message}");
                }
                
                // 使用憑證解密
                try
                {
                    envelopedCms.Decrypt();
                }
                catch (CryptographicException ex)
                {
                    // 如果解密失敗，可能是找不到合適的憑證
                    Console.WriteLine($"使用當前用戶的憑證解密失敗: {ex.Message}");
                    
                    // 嘗試使用PFX/P12檔案解密
                    Console.WriteLine("請選擇包含私鑰的PFX/P12憑證檔案以進行解密...");
                    OpenFileDialog openFileDialog = new OpenFileDialog
                    {
                        Filter = "PFX/P12憑證檔案|*.pfx;*.p12|所有檔案|*.*",
                        Title = "選擇PFX/P12憑證檔案"
                    };
                    
                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        Console.Write("請輸入PFX/P12檔案密碼 (如無密碼請直接按Enter): ");
                        string pfxPassword = ReadPfxPasswordFromConsole();
                        
                        try
                        {
                            X509Certificate2 cert = new X509Certificate2(
                                openFileDialog.FileName, 
                                pfxPassword, 
                                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
                            );
                            
                            // 建立新的EnvelopedCms物件
                            EnvelopedCms newEnvelopedCms = new EnvelopedCms();
                            newEnvelopedCms.Decode(encryptedData);
                            
                            // 使用載入的憑證解密
                            X509Certificate2Collection certificates = new X509Certificate2Collection(cert);
                            newEnvelopedCms.Decrypt(certificates);
                            
                            // 更新解密後的內容
                            envelopedCms = newEnvelopedCms;
                        }
                        catch (Exception pfxEx)
                        {
                            throw new Exception($"使用PFX/P12憑證解密失敗: {pfxEx.Message}");
                        }
                    }
                    else
                    {
                        throw new Exception("解密已取消。找不到適合解密的憑證。");
                    }
                }
                
                // 獲取解密後的內容
                byte[] decryptedContent = envelopedCms.ContentInfo.Content;
                
                // 儲存解密後的檔案
                string outputPath = filePath;
                if (filePath.EndsWith(".cms") || filePath.EndsWith(".p7m") || filePath.EndsWith(".pgp"))
                {
                    outputPath = filePath.Substring(0, filePath.LastIndexOf('.')) + ".decrypted";
                }
                else
                {
                    outputPath = filePath + ".decrypted";
                }
                
                File.WriteAllBytes(outputPath, decryptedContent);
                Console.WriteLine($"檔案解密成功: {outputPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"解密失敗: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"詳細錯誤: {ex.InnerException.Message}");
                }
            }
        }

        // 讀取PFX/P12檔案密碼
        private static string ReadPfxPasswordFromConsole()
        {
            string password = string.Empty;
            ConsoleKeyInfo key;
            
            do
            {
                key = Console.ReadKey(true);
                
                // 處理退格鍵
                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    Console.Write("\b \b");
                    password = password.Substring(0, password.Length - 1);
                }
                // 處理其他按鍵
                else if (!char.IsControl(key.KeyChar))
                {
                    Console.Write("*");
                    password += key.KeyChar;
                }
            } while (key.Key != ConsoleKey.Enter);
            
            Console.WriteLine();
            return password;
        }

        private static X509Certificate2 FindCertificateDirectly(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                return null;
            }

            // 嘗試從個人存放區尋找證書
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                // 處理SHA1指紋 (不區分大小寫並移除空格和冒號)
                string cleanIdentifier = identifier.Replace(" ", "").Replace(":", "").Replace("-", "").ToLowerInvariant();

                // 首先尋找完全匹配的證書指紋
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        string thumbprint = cert.Thumbprint.Replace(" ", "").Replace(":", "").Replace("-", "").ToLowerInvariant();
                        
                        if (string.Equals(thumbprint, cleanIdentifier, StringComparison.OrdinalIgnoreCase))
                        {
                            return new X509Certificate2(cert);
                        }
                    }
                }
                
                // 如果沒有找到匹配的指紋，嘗試主題名稱和序號匹配
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        if (cert.Subject.IndexOf(identifier, StringComparison.OrdinalIgnoreCase) >= 0 ||
                            string.Equals(cert.SerialNumber, identifier, StringComparison.OrdinalIgnoreCase))
                        {
                            return new X509Certificate2(cert);
                        }
                    }
                }
            }

            // 如果找不到匹配的證書，返回null
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

        private static void EncryptFileWithCertFile(string filePath, string certFilePath)
        {
            try
            {
                // 讀取要加密的檔案
                byte[] fileContent = File.ReadAllBytes(filePath);
                
                // 從檔案載入憑證
                X509Certificate2 certificate = null;
                try
                {
                    certificate = new X509Certificate2(certFilePath);
                }
                catch (Exception ex)
                {
                    throw new Exception($"載入憑證檔案失敗: {ex.Message}");
                }
                
                Console.WriteLine($"使用檔案憑證: {certificate.Subject}");
                
                // 建立 EnvelopedCms 物件
                ContentInfo contentInfo = new ContentInfo(fileContent);
                EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);
                
                // 為收件者加密
                CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, certificate);
                envelopedCms.Encrypt(recipient);
                
                // 取得加密後的內容
                byte[] encryptedData = envelopedCms.Encode();
                
                // 儲存加密後的檔案，統一使用 .cms 副檔名
                string outputPath = filePath + ".cms";
                File.WriteAllBytes(outputPath, encryptedData);
                Console.WriteLine($"已加密檔案: {outputPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"使用憑證檔案加密失敗: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"詳細錯誤: {ex.InnerException.Message}");
                }
            }
        }

        // 調試日誌輔助方法 - 只在調試模式下輸出訊息
        private static void DebugLog(string message)
        {
            if (_debugMode)
            {
                Console.WriteLine($"[DEBUG] {message}");
            }
        }

        // 新增幫助方法來獲取簽署時間
        private static DateTime? GetSigningTime(SignerInfo signerInfo)
        {
            foreach (CryptographicAttributeObject attr in signerInfo.SignedAttributes)
            {
                if (attr.Oid.Value == "1.2.840.113549.1.9.5") // signingTime
                {
                    if (attr.Values.Count > 0)
                    {
                        var encodedTime = (Pkcs9SigningTime)attr.Values[0];
                        return encodedTime.SigningTime;
                    }
                }
            }
            
            return null;
        }
    }
} 