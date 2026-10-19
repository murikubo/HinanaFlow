using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HinanaFlow.Core;
using System.Runtime.InteropServices;
namespace HinanaFlow;

// No private-key export. All methods are invoked only by explicit diagnostic UI actions.
public sealed class WindowsIdentityStore
{
    private const string KeyName = "dev.hinana.flow.identity.v1";
    private static string TrustPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HinanaFlow","peer.dpapi");
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    private static byte[] Protect(byte[] bytes, bool decrypt)
    {
        Blob input = new() {Length=bytes.Length,Data=Marshal.AllocHGlobal(bytes.Length)};
        Blob output=default;
        try {
            Marshal.Copy(bytes,0,input.Data,bytes.Length);
            bool ok=decrypt ? CryptUnprotectData(ref input,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output)
                : CryptProtectData(ref input,null,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output);
            if (!ok) throw new CryptographicException("dpapi");
            byte[] result=new byte[output.Length]; Marshal.Copy(output.Data,result,0,result.Length); return result;
        } finally { Marshal.FreeHGlobal(input.Data); if(output.Data!=IntPtr.Zero) LocalFree(output.Data); }
    }
    public X509Certificate2 LoadOrCreate()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        var candidates = store.Certificates.Cast<X509Certificate2>().Where(c => c.FriendlyName == KeyName).ToArray();
        if (candidates.Length > 1) throw new CryptographicException("ambiguous_identity");
        if (candidates.Length == 1)
        {
            var cert = candidates[0];
            using var ecdsa = cert.GetECDsaPrivateKey();
            if (ecdsa is not ECDsaCng cng || cng.Key.KeyName != KeyName || cng.Key.ExportPolicy != CngExportPolicies.None)
                throw new CryptographicException("invalid_identity");
            return cert;
        }
        using CngKey key = CngKey.Exists(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider)
            ? CngKey.Open(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider)
            : CngKey.Create(CngAlgorithm.ECDsaP256, KeyName, new CngKeyCreationParameters
              { Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider, KeyUsage = CngKeyUsages.Signing, ExportPolicy = CngExportPolicies.None });
        if (key.ExportPolicy != CngExportPolicies.None || key.Algorithm != CngAlgorithm.ECDsaP256)
            throw new CryptographicException("invalid_identity");
        using var signing = new ECDsaCng(key);
        var request = new CertificateRequest("CN=Hinana Flow local identity", signing, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {
            new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }, false));
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        created.FriendlyName = KeyName; store.Add(created);
        using var verify = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        verify.Open(OpenFlags.ReadOnly);
        return verify.Certificates.Cast<X509Certificate2>().Single(c => c.Thumbprint == created.Thumbprint);
    }
    public byte[]? TrustedPeer(byte[] localPin)
    {
        if (!File.Exists(TrustPath)) return null;
        var info=new FileInfo(TrustPath);
        if (info.Length is <1 or >4096) throw new CryptographicException("invalid_trust");
        byte[] record=Protect(File.ReadAllBytes(TrustPath),true);
        if (record.Length != 64 || !CryptographicOperations.FixedTimeEquals(record.AsSpan(0,32), localPin))
            throw new CryptographicException("invalid_trust");
        return record[32..];
    }
    public void Confirm(byte[] localPin, byte[] peerPin, bool oobConfirmed, bool mutualTls)
    {
        if (!oobConfirmed || !mutualTls || localPin.Length != 32 || peerPin.Length != 32) throw new CryptographicException("oob_required");
        var old = TrustedPeer(localPin);
        if (old is not null) { if (!CryptographicOperations.FixedTimeEquals(old, peerPin)) throw new CryptographicException("key_changed"); return; }
        Directory.CreateDirectory(Path.GetDirectoryName(TrustPath)!);
        byte[] record=Protect(localPin.Concat(peerPin).ToArray(),false);
        string temporary=TrustPath+".pending-"+Guid.NewGuid().ToString("N");
        try {
            using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {file.Write(record);file.Flush(true);}
            File.Move(temporary,TrustPath,false); // atomic same-directory commit; never overwrite prior trust
        } finally {if(File.Exists(temporary)) File.Delete(temporary);}
    }
    public void ForgetPeer()
    {
        if (File.Exists(TrustPath)) File.Delete(TrustPath);
    }
}
