using Microsoft.UI.Xaml;
using Microsoft.UI.Dispatching;
namespace HinanaFlow;
public partial class App : Application
{
    private Window? window;
    public App() { InitializeComponent(); }
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
        window = new MainWindow(); window.Activate();
    }
}
