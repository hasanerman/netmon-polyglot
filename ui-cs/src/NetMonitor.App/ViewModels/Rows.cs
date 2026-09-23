using NetMonitor.Interop;

namespace NetMonitor.App.ViewModels;

public enum SourceKind
{
    Demo,
    Live,
    File,
}

public sealed record CaptureSource(SourceKind Kind, string Label, string Target, DemoScenario Scenario = DemoScenario.Mixed)
{
    public override string ToString() => Label;
}

public sealed record FlowRow(string Protocol, string EndpointA, string EndpointB, string Packets, string Bytes, string Duration)
{
    public static FlowRow From(FlowInfo f) => new(
        f.ProtocolName,
        f.EndpointA,
        f.EndpointB,
        Format.Count(f.TotalPackets),
        Format.Bytes(f.TotalBytes),
        Format.Seconds(f.Duration));
}

public sealed record AlertRow(
    AlertSeverity Level,
    string Time,
    string Severity,
    string RuleId,
    string Message,
    string Source,
    string Origin,
    string Score)
{
    public static AlertRow From(AlertInfo a) => new(
        a.Severity,
        Format.LocalTime(a.Time),
        a.Severity.ToString().ToUpperInvariant(),
        a.RuleId,
        a.Message,
        a.SourceAddress?.ToString() ?? "-",
        a.Source == AlertSource.Anomaly ? "ml" : "rule",
        Format.Decimal(a.Score, 2));
}
