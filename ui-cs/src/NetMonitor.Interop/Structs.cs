using System.Runtime.InteropServices;

namespace NetMonitor.Interop;

internal static class NativeLimits
{
    public const int AddrLen = 16;
    public const int RuleIdLen = 64;
    public const int MessageLen = 192;
    public const int DeviceNameLen = 256;
    public const uint AbiVersion = 1;
    public const byte FamilyIpv4 = 4;
    public const byte FamilyIpv6 = 6;
    public const uint DeviceLoopback = 0x1;
}

public enum NcStatus
{
    Ok = 0,
    NullArg = -1,
    InvalidArg = -2,
    State = -3,
    Io = -4,
    Capture = -5,
    NoLibrary = -6,
    Permission = -7,
    Panic = -8,
    Rules = -9,
    Format = -10,
}

[StructLayout(LayoutKind.Sequential)]
internal struct NcConfig
{
    public uint MaxFlows;
    public uint FlowIdleTimeoutMs;
    public uint TopN;
    public uint Snaplen;
    public uint LinkType;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NcStats
{
    public ulong Packets;
    public ulong Bytes;
    public ulong Ipv4;
    public ulong Ipv6;
    public ulong Tcp;
    public ulong Udp;
    public ulong Icmp;
    public ulong OtherL4;
    public ulong NonIp;
    public ulong Fragments;
    public ulong Dns;
    public ulong DnsErrors;
    public ulong ParseErrors;
    public ulong ActiveFlows;
    public ulong EvictedFlows;
    public ulong ExpiredFlows;
    public ulong LastTsUs;
    public ulong CaptureDropped;
    public ulong AlertsTotal;
    public ulong AlertsDropped;
    public ulong CaptureState;
    public ulong RulesLoaded;
    public ulong AnalyticsState;
    public ulong AnalyticsSent;
    public ulong AnalyticsDropped;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NcFlow
{
    public fixed byte AAddr[NativeLimits.AddrLen];
    public fixed byte BAddr[NativeLimits.AddrLen];
    public ushort APort;
    public ushort BPort;
    public byte Proto;
    public byte Family;
    public byte TcpFlags;
    public byte Reserved;
    public ulong PacketsAb;
    public ulong PacketsBa;
    public ulong BytesAb;
    public ulong BytesBa;
    public ulong FirstSeenUs;
    public ulong LastSeenUs;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NcAlert
{
    public ulong TsUs;
    public double Score;
    public uint Severity;
    public uint Source;
    public fixed byte SrcAddr[NativeLimits.AddrLen];
    public byte Family;
    public fixed byte Reserved[7];
    public fixed byte RuleId[NativeLimits.RuleIdLen];
    public fixed byte Message[NativeLimits.MessageLen];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NcDevice
{
    public fixed byte Name[NativeLimits.DeviceNameLen];
    public fixed byte Description[NativeLimits.DeviceNameLen];
    public uint Flags;
}
