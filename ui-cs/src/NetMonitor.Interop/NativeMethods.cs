using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NetMonitor.Interop;

internal static unsafe partial class NativeMethods
{
    private const string Lib = "netcore";

    [LibraryImport(Lib, EntryPoint = "core_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial uint AbiVersion();

    [LibraryImport(Lib, EntryPoint = "core_create")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial CoreHandle Create(in NcConfig config);

    [LibraryImport(Lib, EntryPoint = "core_destroy")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void Destroy(nint core);

    [LibraryImport(Lib, EntryPoint = "core_feed_packet")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int FeedPacket(CoreHandle core, ulong tsUs, byte* data, uint caplen, uint wireLen);

    [LibraryImport(Lib, EntryPoint = "core_open_live", StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OpenLive(CoreHandle core, string iface, byte promisc);

    [LibraryImport(Lib, EntryPoint = "core_open_file", StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int OpenFile(CoreHandle core, string path, byte realtime);

    [LibraryImport(Lib, EntryPoint = "core_load_rules", StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int LoadRules(CoreHandle core, string path);

    [LibraryImport(Lib, EntryPoint = "core_connect_analytics", StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int ConnectAnalytics(CoreHandle core, string endpoint);

    [LibraryImport(Lib, EntryPoint = "core_disconnect_analytics")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int DisconnectAnalytics(CoreHandle core);

    [LibraryImport(Lib, EntryPoint = "core_start")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Start(CoreHandle core);

    [LibraryImport(Lib, EntryPoint = "core_stop")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int Stop(CoreHandle core);

    [LibraryImport(Lib, EntryPoint = "core_poll_stats")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int PollStats(CoreHandle core, out NcStats stats);

    [LibraryImport(Lib, EntryPoint = "core_poll_top_flows")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int PollTopFlows(CoreHandle core, NcFlow* flows, uint capacity, out uint written);

    [LibraryImport(Lib, EntryPoint = "core_poll_alert")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int PollAlert(CoreHandle core, out NcAlert alert);

    [LibraryImport(Lib, EntryPoint = "core_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int LastError(CoreHandle core, byte* buffer, uint length);

    [LibraryImport(Lib, EntryPoint = "core_list_devices")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int ListDevices(NcDevice* devices, uint capacity, out uint total);

    [LibraryImport(Lib, EntryPoint = "core_write_demo_pcap", StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int WriteDemoPcap(string path, uint scenario, uint packets, ulong seed);

    [LibraryImport(Lib, EntryPoint = "core_status_str")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nint StatusStr(int status);
}
