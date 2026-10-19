using Microsoft.UI.Xaml;
using HinanaFlow.Core;
namespace HinanaFlow;
public sealed partial class MainWindow : Window
{
    private readonly Discovery discovery;
    private readonly DesktopSession session;
    public MainWindow()
    {
        InitializeComponent();
        session=new DesktopSession(UpdateSession);
        discovery=new Discovery(DispatcherQueue,names=>Peers.ItemsSource=names,status=>Status.Text=status);
        Closed+=(_,_)=>{discovery.Stop();session.Stop();};
        UpdateSession();
    }
    private void UpdateSession()
    {
        Fingerprint.Text=session.Fingerprint; SessionStatus.Text=session.Status; Pending.Text=session.Pending; Received.Text=session.Received;
        PrepareButton.IsEnabled=!session.Busy; ListenButton.IsEnabled=ConnectButton.IsEnabled=!session.Busy && session.Fingerprint.Length==64;
        LocalAddress.IsEnabled=PeerAddress.IsEnabled=Port.IsEnabled=PeerFingerprint.IsEnabled=OobConfirmed.IsEnabled=!session.Busy;
        SendButton.IsEnabled=session.CanSend; ApproveButton.IsEnabled=DenyButton.IsEnabled=session.AwaitingApproval;
        Draft.IsEnabled=session.Connected; if(!session.Busy) Draft.Text="";
    }
    private void PrepareIdentity(object sender,RoutedEventArgs e)
    {
        session.Prepare(); PeerFingerprint.Text=session.SavedFingerprint;
        if(LocalAddress.Text.Length==0) LocalAddress.Text=LanBinding.Addresses().FirstOrDefault() ?? "";
    }
    private async void Listen(object sender,RoutedEventArgs e) => await session.StartAsync(true,LocalAddress.Text,PeerAddress.Text,Port.Text,PeerFingerprint.Text,OobConfirmed.IsChecked==true);
    private async void Connect(object sender,RoutedEventArgs e) => await session.StartAsync(false,LocalAddress.Text,PeerAddress.Text,Port.Text,PeerFingerprint.Text,OobConfirmed.IsChecked==true);
    private void CloseSession(object sender,RoutedEventArgs e) => session.Stop();
    private void ForgetPeer(object sender,RoutedEventArgs e) {session.Forget();PeerFingerprint.Text="";OobConfirmed.IsChecked=false;}
    private async void SendText(object sender,RoutedEventArgs e) {string text=Draft.Text; Draft.Text=""; await session.SendAsync(text);}
    private async void Approve(object sender,RoutedEventArgs e) => await session.DecideAsync(true);
    private async void Deny(object sender,RoutedEventArgs e) => await session.DecideAsync(false);
    private void StartDiscovery(object sender,RoutedEventArgs e)=>discovery.Start();
    private void StopDiscovery(object sender,RoutedEventArgs e)=>discovery.Stop();
}
