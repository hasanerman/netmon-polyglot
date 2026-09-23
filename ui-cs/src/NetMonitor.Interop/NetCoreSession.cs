namespace NetMonitor.Interop;

public sealed unsafe class NetCoreSession : IDisposable
{
    public const int MaxTopFlows = 256;
    private const int ErrorBufferLength = 512;
    private const int AlertDrainLimit = 512;
    private const int DefaultSnaplen = 65535;

    private readonly CoreHandle _handle;

    public NetCoreSession(CoreOptions? options = null)
    {
        uint abi = NativeAbiVersion;
        if (abi != NativeLimits.AbiVersion)
        {
            throw new NetCoreException(NcStatus.State, $"netcore abi {abi}, expected {NativeLimits.AbiVersion}");
        }

        var config = ToConfig(options ?? new CoreOptions());
        _handle = NativeMethods.Create(in config);
        if (_handle.IsInvalid)
        {
            _handle.Dispose();
            throw new NetCoreException(NcStatus.InvalidArg, "core_create rejected the configuration");
        }
    }

    public static uint NativeAbiVersion => NativeMethods.AbiVersion();

    public static IReadOnlyList<DeviceInfo> ListDevices()
    {
        ThrowOnError(NativeMethods.ListDevices(null, 0, out uint total), "device listing failed");
        if (total == 0)
        {
            return [];
        }

        var devices = new NcDevice[total];
        fixed (NcDevice* ptr = devices)
        {
            ThrowOnError(NativeMethods.ListDevices(ptr, total, out total), "device listing failed");
            var result = new List<DeviceInfo>((int)Math.Min(total, (uint)devices.Length));
            for (int i = 0; i < result.Capacity; i++)
            {
                result.Add(Mapping.ToDevice(ptr + i));
            }

            return result;
        }
    }

    public static void WriteDemoPcap(string path, DemoScenario scenario, int packets, ulong seed)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentOutOfRangeException.ThrowIfNegative(packets);
        ThrowOnError(NativeMethods.WriteDemoPcap(path, (uint)scenario, (uint)packets, seed), $"cannot write {path}");
    }

    public void OpenFile(string path, bool realtime = false)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Check(NativeMethods.OpenFile(_handle, path, realtime ? (byte)1 : (byte)0));
    }

    public void OpenLive(string device, bool promiscuous = false)
    {
        ArgumentException.ThrowIfNullOrEmpty(device);
        Check(NativeMethods.OpenLive(_handle, device, promiscuous ? (byte)1 : (byte)0));
    }

    public int LoadRules(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        int active = NativeMethods.LoadRules(_handle, path);
        Check(active);
        return active;
    }

    public void ConnectAnalytics(string endpoint)
    {
        ArgumentException.ThrowIfNullOrEmpty(endpoint);
        Check(NativeMethods.ConnectAnalytics(_handle, endpoint));
    }

    public void DisconnectAnalytics() => Check(NativeMethods.DisconnectAnalytics(_handle));

    public void Start() => Check(NativeMethods.Start(_handle));

    public void Stop() => Check(NativeMethods.Stop(_handle));

    public void Feed(ulong timestampMicros, ReadOnlySpan<byte> frame)
    {
        fixed (byte* data = frame)
        {
            Check(NativeMethods.FeedPacket(_handle, timestampMicros, data, (uint)frame.Length, (uint)frame.Length));
        }
    }

    public TrafficStats PollStats()
    {
        Check(NativeMethods.PollStats(_handle, out var stats));
        return Mapping.ToStats(in stats);
    }

    public IReadOnlyList<FlowInfo> PollTopFlows(int max)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(max);
        int capacity = Math.Min(max, MaxTopFlows);
        if (capacity == 0)
        {
            return [];
        }

        NcFlow* buffer = stackalloc NcFlow[capacity];
        Check(NativeMethods.PollTopFlows(_handle, buffer, (uint)capacity, out uint written));
        var flows = new FlowInfo[written];
        for (int i = 0; i < flows.Length; i++)
        {
            flows[i] = Mapping.ToFlow(buffer + i);
        }

        return flows;
    }

    public IReadOnlyList<AlertInfo> DrainAlerts()
    {
        var alerts = new List<AlertInfo>();
        while (alerts.Count < AlertDrainLimit)
        {
            int rc = NativeMethods.PollAlert(_handle, out var raw);
            Check(rc);
            if (rc == 0)
            {
                break;
            }

            alerts.Add(Mapping.ToAlert(&raw));
        }

        return alerts;
    }

    public void Dispose() => _handle.Dispose();

    private static NcConfig ToConfig(CoreOptions o) => new()
    {
        MaxFlows = checked((uint)o.MaxFlows),
        FlowIdleTimeoutMs = checked((uint)o.FlowIdleTimeout.TotalMilliseconds),
        TopN = checked((uint)o.TopN),
        Snaplen = checked((uint)(o.Snaplen == 0 ? DefaultSnaplen : o.Snaplen)),
    };

    private static void ThrowOnError(int rc, string context)
    {
        if (rc < 0)
        {
            throw new NetCoreException((NcStatus)rc, $"{context}: {Mapping.StatusText(rc)}");
        }
    }

    private void Check(int rc)
    {
        if (rc >= 0)
        {
            return;
        }

        throw new NetCoreException((NcStatus)rc, $"{Mapping.StatusText(rc)}: {LastError()}");
    }

    private string LastError()
    {
        byte* buffer = stackalloc byte[ErrorBufferLength];
        return NativeMethods.LastError(_handle, buffer, ErrorBufferLength) == 0
            ? Mapping.ReadCString(buffer, ErrorBufferLength)
            : string.Empty;
    }
}
