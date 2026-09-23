using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace NetMonitor.Interop;

internal static unsafe class Mapping
{
    private const long TicksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;

    public static DateTimeOffset FromUnixMicros(ulong micros) =>
        DateTimeOffset.UnixEpoch.AddTicks(checked((long)micros * TicksPerMicrosecond));

    public static string ReadCString(byte* bytes, int capacity)
    {
        var span = new ReadOnlySpan<byte>(bytes, capacity);
        int end = span.IndexOf((byte)0);
        return Encoding.UTF8.GetString(end < 0 ? span : span[..end]);
    }

    public static IPAddress? ToAddress(byte* bytes, byte family) => family switch
    {
        NativeLimits.FamilyIpv4 => new IPAddress(new ReadOnlySpan<byte>(bytes, 4)),
        NativeLimits.FamilyIpv6 => new IPAddress(new ReadOnlySpan<byte>(bytes, NativeLimits.AddrLen)),
        _ => null,
    };

    public static TrafficStats ToStats(in NcStats s) => new()
    {
        Packets = s.Packets,
        Bytes = s.Bytes,
        Ipv4 = s.Ipv4,
        Ipv6 = s.Ipv6,
        Tcp = s.Tcp,
        Udp = s.Udp,
        Icmp = s.Icmp,
        OtherL4 = s.OtherL4,
        NonIp = s.NonIp,
        Fragments = s.Fragments,
        Dns = s.Dns,
        DnsErrors = s.DnsErrors,
        ParseErrors = s.ParseErrors,
        ActiveFlows = s.ActiveFlows,
        EvictedFlows = s.EvictedFlows,
        ExpiredFlows = s.ExpiredFlows,
        LastPacketTime = s.LastTsUs == 0 ? null : FromUnixMicros(s.LastTsUs),
        CaptureDropped = s.CaptureDropped,
        AlertsTotal = s.AlertsTotal,
        AlertsDropped = s.AlertsDropped,
        CaptureState = (CaptureState)s.CaptureState,
        RulesLoaded = (int)s.RulesLoaded,
        AnalyticsState = (AnalyticsState)s.AnalyticsState,
        AnalyticsBatchesSent = s.AnalyticsSent,
        AnalyticsBatchesDropped = s.AnalyticsDropped,
    };

    public static FlowInfo ToFlow(NcFlow* f) => new(
        ToAddress(f->AAddr, f->Family) ?? IPAddress.None,
        f->APort,
        ToAddress(f->BAddr, f->Family) ?? IPAddress.None,
        f->BPort,
        f->Proto,
        f->TcpFlags,
        f->PacketsAb,
        f->PacketsBa,
        f->BytesAb,
        f->BytesBa,
        FromUnixMicros(f->FirstSeenUs),
        FromUnixMicros(f->LastSeenUs));

    public static AlertInfo ToAlert(NcAlert* a) => new(
        FromUnixMicros(a->TsUs),
        (AlertSeverity)a->Severity,
        (AlertSource)a->Source,
        ReadCString(a->RuleId, NativeLimits.RuleIdLen),
        ReadCString(a->Message, NativeLimits.MessageLen),
        ToAddress(a->SrcAddr, a->Family),
        a->Score);

    public static DeviceInfo ToDevice(NcDevice* d) => new(
        ReadCString(d->Name, NativeLimits.DeviceNameLen),
        ReadCString(d->Description, NativeLimits.DeviceNameLen),
        (d->Flags & NativeLimits.DeviceLoopback) != 0);

    public static string StatusText(int status) =>
        Marshal.PtrToStringUTF8(NativeMethods.StatusStr(status)) ?? "unknown status";
}
