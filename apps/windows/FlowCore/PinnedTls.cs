using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace HinanaFlow.Core;

public static class PeerPin
{
    public static byte[]? Digest(X509Certificate2 certificate)
    {
        using ECDsa? key = certificate.GetECDsaPublicKey();
        if (key is null || key.KeySize != 256) return null;
        var p = key.ExportParameters(false);
        if (p.Curve.Oid.Value != "1.2.840.10045.3.1.7" || p.Q.X?.Length != 32 || p.Q.Y?.Length != 32) return null;
        byte[] point = new byte[65]; point[0] = 4;
        p.Q.X.CopyTo(point, 1); p.Q.Y.CopyTo(point, 33);
        return SHA256.HashData(point);
    }
    public static bool Verify(X509Certificate? certificate, ReadOnlySpan<byte> expected)
    {
        if (certificate is null || expected.Length != 32) return false;
        try
        {
            using var leaf = new X509Certificate2(certificate);
            var now = DateTime.UtcNow;
            if (now < leaf.NotBefore.ToUniversalTime() || now > leaf.NotAfter.ToUniversalTime()) return false;
            var actual = Digest(leaf);
            return actual is not null && CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (CryptographicException) { return false; }
    }
}

public static class LanAddress
{
    public static bool Permits(IPAddress address)
    {
        var b = address.GetAddressBytes();
        if (b.Length == 4) return b[0] == 10 || b[0] == 172 && b[1] is >=16 and <=31 ||
            b[0] == 192 && b[1] == 168 || b[0] == 169 && b[1] == 254;
        return b.Length == 16 && ((b[0] & 0xfe) == 0xfc || b[0] == 0xfe && (b[1] & 0xc0) == 0x80);
    }
}

public static class PinnedTls
{
    /// Diagnostic only: no application bytes; no untrusted first-pairing path.
    /// Identity must come from an OS protected, nonexportable key; the UI does not call this yet.
    public static async Task ProbeAsync(IPAddress address, int port, byte[] approvedPin,
        X509Certificate2 localIdentity, CancellationToken cancellation)
    {
        if (approvedPin.Length != 32) throw new AuthenticationException("untrusted");
        if (!LanAddress.Permits(address) || port is <1 or >65535) throw new ArgumentException("invalid_address");
        if (!localIdentity.HasPrivateKey) throw new AuthenticationException("missing_identity");
        byte[] pin = approvedPin.ToArray(); // immutable session snapshot
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var socket = new TcpClient(address.AddressFamily);
        await socket.ConnectAsync(address, port, timeout.Token);
        using var tls = new SslStream(socket.GetStream(), false, (_, cert, _, _) => PeerPin.Verify(cert, pin));
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = address.ToString(),
            EnabledSslProtocols = SslProtocols.Tls13,
            ClientCertificates = new X509CertificateCollection { localIdentity },
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            AllowRenegotiation = false, AllowTlsResume = false
        };
        // Local pinned identities have no public CA revocation service. Revocation is local trust removal.
        await tls.AuthenticateAsClientAsync(options, timeout.Token);
        if (tls.SslProtocol != SslProtocols.Tls13 || !tls.IsMutuallyAuthenticated)
            throw new AuthenticationException("mutual_tls_required");
        // Dispose immediately after the handshake. Transfer gate remains closed.
    }
}
