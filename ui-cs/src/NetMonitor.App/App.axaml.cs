using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using NetMonitor.App.ViewModels;
using NetMonitor.App.Views;
using NetMonitor.Interop;

namespace NetMonitor.App;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        LiveCharts.Configure(config => config.AddDarkTheme());

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = CreateMainWindow(desktop);
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static Window CreateMainWindow(IClassicDesktopStyleApplicationLifetime desktop)
    {
        NetCoreSession session;
        try
        {
            session = new NetCoreSession();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or NetCoreException)
        {
            return StartupErrorWindow(ex.Message);
        }

        var vm = new MainViewModel(session, action => Dispatcher.UIThread.Post(action));
        desktop.Exit += (_, _) => vm.Dispose();
        if (AnalyticsEndpoint(desktop.Args) is { } endpoint)
        {
            vm.ConnectAnalytics(endpoint);
        }

        var window = new MainWindow { DataContext = vm };
        if (DemoArgument(desktop.Args) is { } scenario)
        {
            window.Opened += async (_, _) => await vm.StartDemoAsync(scenario).ConfigureAwait(true);
        }

        return window;
    }

    private const string DefaultAnalyticsEndpoint = "http://127.0.0.1:50051";

    private static string? AnalyticsEndpoint(string[]? args)
    {
        args ??= [];
        if (args.Contains("--no-analytics"))
        {
            return null;
        }

        int i = Array.IndexOf(args, "--analytics");
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : DefaultAnalyticsEndpoint;
    }

    private static DemoScenario? DemoArgument(string[]? args)
    {
        int i = Array.IndexOf(args ?? [], "--demo");
        if (args is null || i < 0 || i + 1 >= args.Length)
        {
            return null;
        }

        return args[i + 1] switch
        {
            "portscan" => DemoScenario.PortScan,
            "dnstunnel" => DemoScenario.DnsTunnel,
            "mixed" => DemoScenario.Mixed,
            _ => null,
        };
    }

    private static Window StartupErrorWindow(string message) => new()
    {
        Title = "NetMonitor",
        Width = 520,
        Height = 180,
        Content = new TextBlock
        {
            Text = $"netcore native library could not be loaded:\n{message}",
            TextWrapping = Avalonia.Media.TextWrapping.Wrap,
            Margin = new Thickness(20),
            VerticalAlignment = VerticalAlignment.Center,
        },
    };
}
