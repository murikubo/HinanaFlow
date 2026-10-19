using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HinanaFlow.Core;
namespace HinanaFlow;

// Methods execute on the WinUI synchronization context. No network callback writes UI/state off-thread.
public sealed class DesktopSession(Action changed)
{
    private readonly WindowsIdentityStore store = new();
    private readonly SemaphoreSlim writer = new(1,1);
    private X509Certificate2? identity;
    private byte[] localPin=[];
    private CancellationTokenSource? lifetime;
    private TcpListener? listener;
    private TcpClient? socket;
    private SslStream? tls;
    private TextProtocol protocol = new(false);
    private int generation;
    private double lastActivity;
    public string Status { get; private set; } = "중지됨";
    public string Fingerprint { get; private set; } = "";
    public string SavedFingerprint { get; private set; } = "";
    public string Received { get; private set; } = "";
    public string Pending { get; private set; } = "";
    public bool Busy { get; private set; }
    public bool Connected { get; private set; }
    public bool AwaitingApproval { get; private set; }
    public bool CanSend => Connected && !protocol.HasOutgoing;
    private static double Now => Environment.TickCount64 / 1000.0;
    public void Prepare()
    {
        if(Busy) return;
        try {
            identity=store.LoadOrCreate(); localPin=PeerPin.Digest(identity) ?? throw new CryptographicException("identity");
            Fingerprint=Convert.ToHexString(localPin).ToLowerInvariant();
            SavedFingerprint=store.TrustedPeer(localPin) is byte[] pin ? Convert.ToHexString(pin).ToLowerInvariant() : "";
            Status="신원 준비됨 — 상대 화면에서 전체 지문을 직접 확인하세요";
        } catch { Status="신원 저장소 오류 — 연결 차단"; }
        changed();
    }
    public async Task StartAsync(bool listen, string local, string peer, string port, string expectedPin, bool confirmedOob)
    {
        if(Busy) return;
        int token=++generation;
        CancellationTokenSource? owned=null;
        TcpListener? ownedListener=null; TcpClient? ownedSocket=null; SslStream? ownedTls=null;
        try {
            if(!OperatingSystem.IsWindowsVersionAtLeast(10,0,22000)) throw new PlatformNotSupportedException("TLS13_requires_Windows11");
            if(identity is null || expectedPin.Length!=64 || !expectedPin.All(Uri.IsHexDigit)) throw new AuthenticationException("oob");
            var sessionIdentity=identity;
            byte[] pin=Convert.FromHexString(expectedPin);
            if(CryptographicOperations.FixedTimeEquals(pin,localPin)) throw new AuthenticationException("self");
            var old=store.TrustedPeer(localPin);
            if(old is not null && !CryptographicOperations.FixedTimeEquals(old,pin)) throw new AuthenticationException("key_changed");
            if(old is null && !confirmedOob) throw new AuthenticationException("oob_required");
            var binding=new LanBinding(IPAddress.Parse(local),IPAddress.Parse(peer),int.Parse(port)); binding.Validate();
            Busy=true; Status=listen ? "최대 60초간 TLS 연결 대기" : "TLS 상호 인증 중"; changed();
            var sessionLifetime=new CancellationTokenSource(); owned=sessionLifetime; lifetime=sessionLifetime;
            using var setup=CancellationTokenSource.CreateLinkedTokenSource(sessionLifetime.Token);
            if(listen) {
                setup.CancelAfter(TimeSpan.FromSeconds(60)); ownedListener=new TcpListener(binding.Local,binding.Port); listener=ownedListener; ownedListener.Start(1);
                while(true) {
                    var candidate=await ownedListener.AcceptTcpClientAsync(setup.Token);
                    if(token!=generation) {candidate.Dispose();return;}
                    if(((IPEndPoint?)candidate.Client.RemoteEndPoint)?.Address.Equals(binding.Peer)==true) { ownedSocket=candidate; socket=candidate; break; }
                    candidate.Dispose();
                }
                ownedListener.Stop(); if(ReferenceEquals(listener,ownedListener)) listener=null;
            } else {
                setup.CancelAfter(TimeSpan.FromSeconds(10)); ownedSocket=new TcpClient(AddressFamily.InterNetwork); socket=ownedSocket;
                ownedSocket.Client.Bind(new IPEndPoint(binding.Local,0));
                await ownedSocket.ConnectAsync(binding.Peer,binding.Port,setup.Token);
                if(token!=generation) return;
            }
            setup.CancelAfter(TimeSpan.FromSeconds(10));
            var active=new SslStream(ownedSocket!.GetStream(),false,(_,cert,_,_)=>PeerPin.Verify(cert,pin)); ownedTls=active; tls=active;
            var chainPolicy=new X509ChainPolicy { DisableCertificateDownloads=true, RevocationMode=X509RevocationMode.NoCheck };
            if(listen) {
                await active.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {
                    ServerCertificate=sessionIdentity, ClientCertificateRequired=true, EnabledSslProtocols=SslProtocols.Tls13,
                    CertificateRevocationCheckMode=X509RevocationMode.NoCheck, CertificateChainPolicy=chainPolicy, AllowRenegotiation=false, AllowTlsResume=false
                },setup.Token);
            } else {
                await active.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                    TargetHost=binding.Peer.ToString(), ClientCertificates=new X509CertificateCollection {sessionIdentity},
                    LocalCertificateSelectionCallback=(_,_,_,_,_)=>sessionIdentity,
                    EnabledSslProtocols=SslProtocols.Tls13, CertificateRevocationCheckMode=X509RevocationMode.NoCheck,
                    CertificateChainPolicy=chainPolicy, AllowRenegotiation=false, AllowTlsResume=false
                },setup.Token);
            }
            if(active.SslProtocol!=SslProtocols.Tls13 || !active.IsMutuallyAuthenticated) throw new AuthenticationException("mutual_tls");
            if(token!=generation) return;
            store.Confirm(localPin,pin,old is not null || confirmedOob,true);
            SavedFingerprint=Convert.ToHexString(pin).ToLowerInvariant();
            protocol=new(true); lastActivity=Now; Connected=true; Status="상호 TLS 1.3 인증됨 · 텍스트 수신은 건별 승인 필요"; changed();
            sessionLifetime.CancelAfter(TimeSpan.FromMinutes(10));
            var watchdog=WatchAsync(token,sessionLifetime.Token);
            try { await ReceiveAsync(active,token,sessionLifetime.Token); }
            finally { sessionLifetime.Cancel(); await watchdog; }
        } catch(OperationCanceledException) { if(token==generation) Stop("시간 제한 또는 사용자 취소로 종료됨"); }
        catch { if(token==generation) Stop("인증·LAN 주소·프로토콜 검증 실패 — 연결 종료"); }
        finally { if(token==generation) Stop("연결 종료됨"); ownedListener?.Stop(); ownedTls?.Dispose(); ownedSocket?.Dispose(); owned?.Dispose(); }
    }
    private async Task WatchAsync(int token, CancellationToken cancel)
    {
        try {
            using var timer=new PeriodicTimer(TimeSpan.FromSeconds(1));
            while(await timer.WaitForNextTickAsync(cancel)) {
                if(token!=generation) return;
                if(protocol.Expired(Now) || Now-lastActivity >= 90) { Stop("텍스트 승인 또는 전송 시간 초과"); return; }
            }
        } catch(OperationCanceledException) { }
    }
    private async Task ReceiveAsync(SslStream active, int token, CancellationToken cancel)
    {
        while(token==generation) {
            byte[] header=new byte[5];
            // WatchAsync bounds idle time using both read and write activity; no slow-drip reset.
            await active.ReadExactlyAsync(header.AsMemory(0,1),cancel);
            using var frameDeadline=CancellationTokenSource.CreateLinkedTokenSource(cancel);
            frameDeadline.CancelAfter(TimeSpan.FromSeconds(10));
            await active.ReadExactlyAsync(header.AsMemory(1,4),frameDeadline.Token);
            uint length=System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1));
            if(header[0]!=1 || length is 0 or >65536) throw new InvalidDataException("frame");
            byte[] payload=new byte[(int)length]; await active.ReadExactlyAsync(payload,frameDeadline.Token);
            if(token!=generation) return;
            var message=ControlJson.Parse(payload); lastActivity=Now;
            foreach(var e in protocol.Receive(message,Now)) {
                if(token!=generation) return;
                switch(e.Kind) {
                    case "send": await WriteAsync(e.Message!,token,cancel); break;
                    case "consent": AwaitingApproval=true; Pending=$"텍스트 수신 제안: {e.ScalarCount}자 / {e.ByteCount} bytes"; break;
                    case "received": Received=e.Text!; AwaitingApproval=false; Pending="수신 완료"; break;
                    case "delivered": Status="상대 수신 확인 완료"; break;
                    case "denied": Status="텍스트 제안이 거부 또는 취소됨"; AwaitingApproval=protocol.NeedsConsent; break;
                }
            }
            if(token!=generation) return;
            changed();
        }
    }
    private async Task WriteAsync(ControlMessage message, int token, CancellationToken cancel)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel); deadline.CancelAfter(TimeSpan.FromSeconds(10));
        await writer.WaitAsync(deadline.Token);
        try {
            if(!Connected || token!=generation || tls is null) throw new AuthenticationException("closed");
            lastActivity=Now;
            await tls.WriteAsync(ControlDecoder.Encode(message.Encode()),deadline.Token);
        } finally {writer.Release();}
    }
    public async Task SendAsync(string text)
    {
        int token=generation;
        try {
            var offer=protocol.Offer(text,Now); changed();
            await WriteAsync(offer,token,lifetime?.Token ?? new CancellationToken(true));
            if(token==generation) {Status="본문 전송 전 상대 승인 대기"; changed();}
        } catch {if(token==generation) Stop("텍스트 제안 실패 — 연결 종료");}
    }
    public async Task DecideAsync(bool accept)
    {
        int token=generation;
        try {
            var m=protocol.Decide(accept,Now); AwaitingApproval=false; Pending=accept ? "본문 수신 대기" : "수신 거부됨"; changed();
            await WriteAsync(m,token,lifetime?.Token ?? new CancellationToken(true));
        } catch {if(token==generation) Stop("수신 승인 실패 — 연결 종료");}
    }
    public void Forget()
    {
        Stop();
        try {store.ForgetPeer();SavedFingerprint="";Status="상대 신뢰 삭제됨 — 재확인 필요";}
        catch {Status="신뢰 삭제 실패";} changed();
    }
    public void Stop(string reason="중지됨")
    {
        generation++; lifetime?.Cancel(); lifetime=null;
        listener?.Stop(); listener=null; tls?.Dispose(); tls=null; socket?.Dispose(); socket=null;
        protocol=new(false); Connected=false; Busy=false; AwaitingApproval=false; Received=""; Pending=""; Status=reason; changed();
    }
}
