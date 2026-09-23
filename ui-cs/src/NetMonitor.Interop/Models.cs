using System.Net;

namespace NetMonitor.Interop;

public enum AlertSeverity
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum AlertSource
{
    Rule = 0,
    Anomaly = 1,
}

public enum CaptureState
{
    Idle = 0,
    Running = 1,
    Finished = 2,
    Failed = 3,
}

public enum AnalyticsState
{
    Off = 0,
    Connecting = 1,
    Connected = 2,
}

public enum DemoScenario
{
    Mixed = 0,
    PortScan = 1,
    DnsTunnel = 2,
}

public sealed record CoreOptions
{
    public int MaxFlows { get; init; }
    public TimeSpan FlowIdleTimeout { get; init; }
    public int TopN { get; init; }
    public int Snaplen { get; init; }
}

public sealed record TrafficStats
{
    public ulong Packets { get; init; }
    public ulong Bytes { get; init; }
    public ulong Ipv4 { get; init; }
    public ulong Ipv6 { get; init; }
    public ulong Tcp { get; init; }
    public ulong Udp { get; init; }
    public ulong Icmp { get; init; }
    public ulong OtherL4 { get; init; }
    public ulong NonIp { get; init; }
    public ulong Fragments { get; init; }
    public ulong Dns { get; init; }
    public ulong DnsErrors { get; init; }
    public ulong ParseErrors { get; init; }
    public ulong ActiveFlows { get; init; }
    public ulong EvictedFlows { get; init; }
    public ulong ExpiredFlows { get; init; }
    public DateTimeOffset? LastPacketTime { get; init; }
    public ulong CaptureDropped { get; init; }
    public ulong AlertsTotal { get; init; }
    public ulong AlertsDropped { get; init; }
    public CaptureState CaptureState { get; init; }
    public int RulesLoaded { get; init; }
    public AnalyticsState AnalyticsState { get; init; }
    public ulong AnalyticsBatchesSent { get; init; }
    public ulong AnalyticsBatchesDropped { get; init; }
}

public sealed record FlowInfo(
    IPAddress AddressA,
    int PortA,
    IPAddress AddressB,
    int PortB,
    byte Protocol,
    byte TcpFlags,
    ulong PacketsAToB,
    ulong PacketsBToA,
    ulong BytesAToB,
    ulong BytesBToA,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen)
{
    public ulong TotalPackets => PacketsAToB + PacketsBToA;

    public ulong TotalBytes => BytesAToB + BytesBToA;

    public TimeSpan Duration => LastSeen - FirstSeen;

    public string ProtocolName => Protocol switch
    {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => Protocol.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    public string EndpointA => FormatEndpoint(AddressA, PortA);

    public string EndpointB => FormatEndpoint(AddressB, PortB);

    private static string FormatEndpoint(IPAddress address, int port) =>
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}"
            : $"{address}:{port}";
}

public sealed record AlertInfo(
    DateTimeOffset Time,
    AlertSeverity Severity,
    AlertSource Source,
    string RuleId,
    string Message,
    IPAddress? SourceAddress,
    double Score);

public sealed record DeviceInfo(string Name, string Description, bool IsLoopback)
{
    public string DisplayName => string.IsNullOrEmpty(Description) ? Name : Description;
}

public readonly record struct TrafficRate(double PacketsPerSecond, double BytesPerSecond);

public sealed record TrafficSnapshot(
    TrafficStats Stats,
    IReadOnlyList<FlowInfo> TopFlows,
    IReadOnlyList<AlertInfo> NewAlerts,
    TrafficRate Rate,
    DateTimeOffset TakenAt);
