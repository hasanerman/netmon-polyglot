using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.Measure;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using NetMonitor.Interop;
using SkiaSharp;

namespace NetMonitor.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    public const int ChartPoints = 300;
    public const int TopFlowCount = 12;
    private const int DemoPackets = 60_000;
    private const ulong DemoSeed = 7;
    private const byte FillAlpha = 40;
    private const float LineWidth = 2;
    private const double DonutInnerRadius = 38;
    private const double Percent = 100;

    private static readonly SKColor Accent = SKColor.Parse("#22D3EE");
    private static readonly SKColor Accent2 = SKColor.Parse("#A78BFA");
    private static readonly SKColor Green = SKColor.Parse("#34D399");
    private static readonly SKColor Amber = SKColor.Parse("#FBBF24");
    private static readonly SKColor Grey = SKColor.Parse("#64748B");
    private static readonly SKColor GridLine = SKColor.Parse("#1F2A44");
    private static readonly SKColor AxisText = SKColor.Parse("#8B9BB4");

    private readonly NetCoreSession _session;
    private readonly StatsPoller _poller;
    private readonly Action<Action> _dispatch;
    private readonly ObservableCollection<double> _packetRate = [];
    private readonly ObservableCollection<double> _megabitRate = [];
    private readonly ObservableValue _tcp = new(0);
    private readonly ObservableValue _udp = new(0);
    private readonly ObservableValue _icmp = new(0);
    private readonly ObservableValue _other = new(0);
    private static readonly TimeSpan RulesReloadDebounce = TimeSpan.FromMilliseconds(300);
    private FileSystemWatcher? _rulesWatcher;
    private CancellationTokenSource? _reloadDebounce;
    private bool _stopping;

    public MainViewModel(NetCoreSession session, Action<Action> dispatch)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(dispatch);
        _session = session;
        _dispatch = dispatch;
        _poller = new StatsPoller(session, topFlows: TopFlowCount);
        _poller.SnapshotReady += (_, snapshot) => _dispatch(() => Apply(snapshot));
        _poller.Faulted += (_, ex) => _dispatch(() => StatusMessage = ex.Message);

        RateSeries = BuildRateSeries();
        ProtocolSeries = BuildProtocolSeries();
        StatusMessage = "Pick a source and press Start";
        PacketRate = "0";
        Throughput = "0.00";
        ActiveFlows = "0";
        TotalPackets = "0";
        TotalBytes = "0 B";
        ParseErrors = "0";
        Dropped = "0";
        (TcpShare, UdpShare, IcmpShare, OtherShare) = ("0.0%", "0.0%", "0.0%", "0.0%");
        RealtimeReplay = true;
        RulesInfo = $"rules: built-in ({session.PollStats().RulesLoaded})";
        AnalyticsInfo = "ml: off";
        LoadSources();
    }

    public ObservableCollection<CaptureSource> Sources { get; } = [];

    public ObservableCollection<FlowRow> TopFlows { get; } = [];

    public AlertsViewModel Alerts { get; } = new();

    public ISeries[] RateSeries { get; }

    public ISeries[] ProtocolSeries { get; }

    public Axis[] RateXAxes { get; } = [new Axis { IsVisible = false }];

    public Axis[] RateYAxes { get; } =
    [
        new Axis
        {
            Name = "packets/s",
            MinLimit = 0,
            TextSize = 11,
            NameTextSize = 11,
            LabelsPaint = new SolidColorPaint(AxisText),
            NamePaint = new SolidColorPaint(Accent),
            SeparatorsPaint = new SolidColorPaint(GridLine),
        },
        new Axis
        {
            Name = "Mbit/s",
            MinLimit = 0,
            TextSize = 11,
            NameTextSize = 11,
            Position = AxisPosition.End,
            ShowSeparatorLines = false,
            LabelsPaint = new SolidColorPaint(AxisText),
            NamePaint = new SolidColorPaint(Accent2),
        },
    ];

    public Func<Task<string?>>? PickCaptureFile { get; set; }

    public Func<Task<string?>>? PickRulesFile { get; set; }

    [ObservableProperty]
    public partial string RulesInfo { get; set; }

    [ObservableProperty]
    public partial string AnalyticsInfo { get; set; }

    public void ConnectAnalytics(string endpoint)
    {
        try
        {
            _session.ConnectAnalytics(endpoint);
            AnalyticsInfo = "ml: connecting";
        }
        catch (NetCoreException ex)
        {
            AnalyticsInfo = "ml: off";
            StatusMessage = ex.Message;
        }
    }

    private static string DescribeAnalytics(TrafficStats s) => s.AnalyticsState switch
    {
        AnalyticsState.Connected => $"ml: connected ({Format.Count(s.AnalyticsBatchesSent)} batches)",
        AnalyticsState.Connecting => "ml: waiting for python service",
        _ => "ml: off",
    };

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartCommand))]
    public partial CaptureSource? SelectedSource { get; set; }

    [ObservableProperty]
    public partial bool RealtimeReplay { get; set; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartCommand), nameof(StopCommand), nameof(BrowseFileCommand))]
    public partial bool IsCapturing { get; set; }

    [ObservableProperty]
    public partial string StatusMessage { get; set; }

    [ObservableProperty]
    public partial string PacketRate { get; set; }

    [ObservableProperty]
    public partial string Throughput { get; set; }

    [ObservableProperty]
    public partial string ActiveFlows { get; set; }

    [ObservableProperty]
    public partial string TotalPackets { get; set; }

    [ObservableProperty]
    public partial string TotalBytes { get; set; }

    [ObservableProperty]
    public partial string ParseErrors { get; set; }

    [ObservableProperty]
    public partial string Dropped { get; set; }

    [ObservableProperty]
    public partial string TcpShare { get; set; }

    [ObservableProperty]
    public partial string UdpShare { get; set; }

    [ObservableProperty]
    public partial string IcmpShare { get; set; }

    [ObservableProperty]
    public partial string OtherShare { get; set; }

    public void Apply(TrafficSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var s = snapshot.Stats;
        PacketRate = Format.Count(snapshot.Rate.PacketsPerSecond);
        double mbps = Format.Megabits(snapshot.Rate.BytesPerSecond);
        Throughput = Format.Decimal(mbps, 2);
        ActiveFlows = Format.Count(s.ActiveFlows);
        TotalPackets = Format.Count(s.Packets);
        TotalBytes = Format.Bytes(s.Bytes);
        ParseErrors = Format.Count(s.ParseErrors);
        Dropped = Format.Count(s.CaptureDropped);
        AnalyticsInfo = DescribeAnalytics(s);

        Push(_packetRate, snapshot.Rate.PacketsPerSecond);
        Push(_megabitRate, mbps);
        (_tcp.Value, _udp.Value, _icmp.Value, _other.Value) = (s.Tcp, s.Udp, s.Icmp, s.OtherL4 + s.NonIp);
        UpdateShares(s);

        TopFlows.Clear();
        foreach (var flow in snapshot.TopFlows)
        {
            TopFlows.Add(FlowRow.From(flow));
        }

        Alerts.Add(snapshot.NewAlerts);
        HandleCaptureState(s.CaptureState);
    }

    public void Dispose()
    {
        _rulesWatcher?.Dispose();
        _poller.StopAsync().GetAwaiter().GetResult();
        _session.Dispose();
    }

    [RelayCommand]
    private async Task LoadRulesAsync()
    {
        if (PickRulesFile is null || await PickRulesFile().ConfigureAwait(true) is not { } path)
        {
            return;
        }

        if (ApplyRules(path))
        {
            WatchRules(path);
        }
    }

    private bool ApplyRules(string path)
    {
        try
        {
            int active = _session.LoadRules(path);
            RulesInfo = $"rules: {Path.GetFileName(path)} ({active})";
            StatusMessage = $"Loaded {active} rule(s) from {path}";
            return true;
        }
        catch (NetCoreException ex)
        {
            StatusMessage = ex.Message;
            return false;
        }
    }

    private void WatchRules(string path)
    {
        _rulesWatcher?.Dispose();
        _rulesWatcher = new FileSystemWatcher(Path.GetDirectoryName(Path.GetFullPath(path))!, Path.GetFileName(path))
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
            EnableRaisingEvents = true,
        };
        _rulesWatcher.Changed += (_, _) => _dispatch(() => ScheduleRulesReload(path));
    }

    private void ScheduleRulesReload(string path)
    {
        // editorler dosyayi birkac kez yaziyor, son yazmayi bekle
        _reloadDebounce?.Cancel();
        _reloadDebounce?.Dispose();
        _reloadDebounce = new CancellationTokenSource();
        var token = _reloadDebounce.Token;
        _ = Task.Delay(RulesReloadDebounce, token).ContinueWith(
            _ => _dispatch(() => ApplyRules(path)),
            token,
            TaskContinuationOptions.OnlyOnRanToCompletion,
            TaskScheduler.Default);
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartAsync()
    {
        if (SelectedSource is not { } source)
        {
            return;
        }

        try
        {
            await OpenSourceAsync(source).ConfigureAwait(true);
            ResetView();
            _session.Start();
            _poller.Start();
            IsCapturing = true;
            StatusMessage = $"Capturing from {source.Label}";
        }
        catch (NetCoreException ex)
        {
            StatusMessage = Describe(ex);
        }
    }

    private bool CanStart() => !IsCapturing && SelectedSource is not null;

    public Task StartDemoAsync(DemoScenario scenario)
    {
        SelectedSource = Sources.First(s => s.Kind == SourceKind.Demo && s.Scenario == scenario);
        return StartAsync();
    }

    [RelayCommand(CanExecute = nameof(IsCapturing))]
    private Task StopAsync() => StopCaptureAsync("Capture stopped");

    [RelayCommand(CanExecute = nameof(CanBrowse))]
    private async Task BrowseFileAsync()
    {
        if (PickCaptureFile is null || await PickCaptureFile().ConfigureAwait(true) is not { } path)
        {
            return;
        }

        var source = new CaptureSource(SourceKind.File, $"File: {Path.GetFileName(path)}", path);
        Sources.Add(source);
        SelectedSource = source;
    }

    private bool CanBrowse() => !IsCapturing;

    private async Task OpenSourceAsync(CaptureSource source)
    {
        switch (source.Kind)
        {
            case SourceKind.Live:
                _session.OpenLive(source.Target);
                break;
            case SourceKind.File:
                _session.OpenFile(source.Target, RealtimeReplay);
                break;
            case SourceKind.Demo:
                StatusMessage = "Generating demo traffic...";
                string path = source.Target;
                await Task.Run(() => NetCoreSession.WriteDemoPcap(path, source.Scenario, DemoPackets, DemoSeed)).ConfigureAwait(true);
                _session.OpenFile(path, realtime: true);
                break;
        }
    }

    private async Task StopCaptureAsync(string message)
    {
        if (!IsCapturing || _stopping)
        {
            return;
        }

        _stopping = true;
        try
        {
            await _poller.StopAsync().ConfigureAwait(true);
            try
            {
                _session.Stop();
            }
            catch (NetCoreException ex)
            {
                message = Describe(ex);
            }

            IsCapturing = false;
            Apply(_poller.PollOnce());
            StatusMessage = message;
        }
        finally
        {
            _stopping = false;
        }
    }

    private void HandleCaptureState(CaptureState state)
    {
        if (!IsCapturing)
        {
            return;
        }

        if (state == CaptureState.Finished)
        {
            _ = StopCaptureAsync("Replay finished");
        }
        else if (state == CaptureState.Failed)
        {
            _ = StopCaptureAsync("Capture failed");
        }
    }

    private void LoadSources()
    {
        string temp = Path.GetTempPath();
        Sources.Add(new CaptureSource(SourceKind.Demo, "Demo: port scan", Path.Combine(temp, "netmonitor-portscan.pcap"), DemoScenario.PortScan));
        Sources.Add(new CaptureSource(SourceKind.Demo, "Demo: dns tunnel", Path.Combine(temp, "netmonitor-dnstunnel.pcap"), DemoScenario.DnsTunnel));
        Sources.Add(new CaptureSource(SourceKind.Demo, "Demo: normal traffic", Path.Combine(temp, "netmonitor-mixed.pcap"), DemoScenario.Mixed));

        try
        {
            foreach (var device in NetCoreSession.ListDevices())
            {
                Sources.Add(new CaptureSource(SourceKind.Live, $"Live: {device.DisplayName}", device.Name));
            }
        }
        catch (NetCoreException ex)
        {
            StatusMessage = $"Live capture unavailable: {ex.Message}";
        }

        SelectedSource = Sources[0];
    }

    private void ResetView()
    {
        _packetRate.Clear();
        _megabitRate.Clear();
        TopFlows.Clear();
        Alerts.Clear();
    }

    private void UpdateShares(TrafficStats s)
    {
        double total = Math.Max(1, s.Tcp + s.Udp + s.Icmp + s.OtherL4 + s.NonIp);
        TcpShare = Share(s.Tcp, total);
        UdpShare = Share(s.Udp, total);
        IcmpShare = Share(s.Icmp, total);
        OtherShare = Share(s.OtherL4 + s.NonIp, total);
    }

    private static string Share(double part, double total) => Format.Decimal(part / total * Percent, 1) + "%";

    private static void Push(ObservableCollection<double> series, double value)
    {
        series.Add(value);
        if (series.Count > ChartPoints)
        {
            series.RemoveAt(0);
        }
    }

    private static string Describe(NetCoreException ex) => ex.Status switch
    {
        NcStatus.Permission => "Permission denied: run as administrator (Windows) or root (Linux)",
        NcStatus.NoLibrary => "Npcap/libpcap is not installed; demo and file replay still work",
        _ => ex.Message,
    };

    private ISeries[] BuildRateSeries() =>
    [
        new LineSeries<double>
        {
            Name = "packets/s",
            Values = _packetRate,
            GeometrySize = 0,
            LineSmoothness = 0.4,
            Stroke = new SolidColorPaint(Accent) { StrokeThickness = LineWidth },
            Fill = new SolidColorPaint(Accent.WithAlpha(FillAlpha)),
            GeometryFill = null,
            GeometryStroke = null,
            ScalesYAt = 0,
            AnimationsSpeed = TimeSpan.Zero,
        },
        new LineSeries<double>
        {
            Name = "Mbit/s",
            Values = _megabitRate,
            GeometrySize = 0,
            LineSmoothness = 0.4,
            Stroke = new SolidColorPaint(Accent2) { StrokeThickness = LineWidth },
            Fill = null,
            GeometryFill = null,
            GeometryStroke = null,
            ScalesYAt = 1,
            AnimationsSpeed = TimeSpan.Zero,
        },
    ];

    private ISeries[] BuildProtocolSeries() =>
    [
        Slice("TCP", _tcp, Accent),
        Slice("UDP", _udp, Accent2),
        Slice("ICMP", _icmp, Green),
        Slice("Other", _other, Grey),
    ];

    private static PieSeries<ObservableValue> Slice(string name, ObservableValue value, SKColor color) => new()
    {
        Name = name,
        Values = [value],
        InnerRadius = DonutInnerRadius,
        Fill = new SolidColorPaint(color),
        Stroke = null,
        DataLabelsPaint = null,
        ToolTipLabelFormatter = point => $"{point.Coordinate.PrimaryValue:N0}",
    };

    public static SKColor SeverityColor(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => SKColor.Parse("#F87171"),
        AlertSeverity.High => Amber,
        AlertSeverity.Medium => Accent2,
        _ => Accent,
    };
}
