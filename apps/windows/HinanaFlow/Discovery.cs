using Microsoft.UI.Dispatching;
using Windows.Devices.Enumeration;
namespace HinanaFlow;

// Native DNS-SD candidate enumeration. No auto pairing, connection, or network data logging.
public sealed class Discovery
{
    private readonly DispatcherQueue dispatcher;
    private readonly Action<string[]> publish;
    private readonly Action<string> status;
    private readonly Dictionary<string, string> candidates = new(); // UI thread only
    private DeviceWatcher? watcher;
    private DispatcherQueueTimer? expiry;
    private int generation;
    private const string Selector = "System.Devices.AepService.ProtocolId:=\"{4526e8c1-8aac-4153-9b16-55e86ada0e54}\" AND System.Devices.Dnssd.ServiceName:=\"_hinanaflow._tcp\" AND System.Devices.Dnssd.Domain:=\"local\"";
    public Discovery(DispatcherQueue dispatcher, Action<string[]> publish, Action<string> status)
    { this.dispatcher = dispatcher; this.publish = publish; this.status = status; }
    public void Start()
    {
        Stop(); candidates.Clear(); publish([]); int token = generation;
        try
        {
            var next = DeviceInformation.CreateWatcher(Selector, ["System.Devices.Dnssd.ServiceName"], DeviceInformationKind.AssociationEndpointService);
            watcher = next;
            next.Added += (_, info) => dispatcher.TryEnqueue(() =>
            {
                if (token != generation || candidates.Count >= 128) return;
                candidates[info.Id] = new string(info.Name.Where(c => !char.IsControl(c)).Take(128).ToArray()) + " · 미인증";
                publish(candidates.Values.OrderBy(n => n).ToArray());
            });
            next.Updated += (_, _) => { }; // Endpoint resolution is a separate reviewed stage.
            next.Removed += (_, info) => dispatcher.TryEnqueue(() =>
            { if (token == generation) { candidates.Remove(info.Id); publish(candidates.Values.ToArray()); } });
            next.EnumerationCompleted += (_, _) => { };
            next.Stopped += (_, _) => dispatcher.TryEnqueue(() =>
            { if (token == generation) { Stop(); status("탐색 종료"); } });
            next.Start(); status("탐색 중 — 발견된 기기는 인증되지 않았습니다");
            expiry = dispatcher.CreateTimer(); expiry.Interval = TimeSpan.FromSeconds(30); expiry.IsRepeating = false;
            expiry.Tick += (_, _) => Stop(); expiry.Start();
        }
        catch (Exception) { Stop(); status("탐색 실패 — 로컬 네트워크 설정을 확인하세요"); }
    }
    public void Stop()
    {
        generation++; expiry?.Stop(); expiry = null;
        var old = watcher; watcher = null;
        if (old?.Status is DeviceWatcherStatus.Started or DeviceWatcherStatus.EnumerationCompleted) old.Stop();
        status("중지됨");
    }
}
