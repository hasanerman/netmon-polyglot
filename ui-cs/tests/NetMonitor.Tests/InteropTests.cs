using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Time.Testing;
using NetMonitor.Interop;

namespace NetMonitor.Tests;

public class InteropTests
{
    private const int SampleFrames = 200;
    private static readonly TimeSpan WaitLimit = TimeSpan.FromSeconds(10);

    internal static string SamplePcap()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "sniffer-c")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return Path.Combine(dir.FullName, "sniffer-c", "tests", "data", "sample.pcap");
    }

    internal static byte[] TcpFrame(byte srcLast, ushort srcPort, byte dstLast, ushort dstPort, byte flags)
    {
        var frame = new byte[14 + 20 + 20];
        frame[12] = 0x08;
        frame[14] = 0x45;
        frame[16] = 0;
        frame[17] = 40;
        frame[22] = 64;
        frame[23] = 6;
        frame[26] = 10;
        frame[29] = srcLast;
        frame[30] = 10;
        frame[33] = dstLast;
        frame[34] = (byte)(srcPort >> 8);
        frame[35] = (byte)srcPort;
        frame[36] = (byte)(dstPort >> 8);
        frame[37] = (byte)dstPort;
        frame[46] = 0x50;
        frame[47] = flags;
        return frame;
    }

    [Fact]
    public void Struct_sizes_match_the_rust_contract()
    {
        Assert.Equal(20, Unsafe.SizeOf<NcConfig>());
        Assert.Equal(200, Unsafe.SizeOf<NcStats>());
        Assert.Equal(88, Unsafe.SizeOf<NcFlow>());
        Assert.Equal(304, Unsafe.SizeOf<NcAlert>());
        Assert.Equal(516, Unsafe.SizeOf<NcDevice>());
        Assert.Equal(1u, NetCoreSession.NativeAbiVersion);
    }

    [Fact]
    public void Feed_produces_stats_and_bidirectional_flow()
    {
        using var session = new NetCoreSession();
        session.Feed(1_000, TcpFrame(1, 40000, 2, 443, 0x02));
        session.Feed(2_000, TcpFrame(2, 443, 1, 40000, 0x12));
        session.Feed(3_000, new byte[] { 1, 2, 3 });

        var stats = session.PollStats();
        Assert.Equal(3ul, stats.Packets);
        Assert.Equal(2ul, stats.Tcp);
        Assert.Equal(1ul, stats.ParseErrors);
        Assert.Equal(1ul, stats.ActiveFlows);
        Assert.Equal(DateTimeOffset.UnixEpoch.AddMilliseconds(3), stats.LastPacketTime);

        var flow = Assert.Single(session.PollTopFlows(10));
        Assert.Equal(IPAddress.Parse("10.0.0.1"), flow.AddressA);
        Assert.Equal(40000, flow.PortA);
        Assert.Equal("TCP", flow.ProtocolName);
        Assert.Equal(1ul, flow.PacketsAToB);
        Assert.Equal(1ul, flow.PacketsBToA);
        Assert.Equal("10.0.0.2:443", flow.EndpointB);
    }

    [Fact]
    public async Task File_replay_goes_through_c_sniffer_and_rust_core()
    {
        using var session = new NetCoreSession();
        session.OpenFile(SamplePcap());
        session.Start();

        var deadline = DateTime.UtcNow + WaitLimit;
        while (session.PollStats().CaptureState == CaptureState.Running && DateTime.UtcNow < deadline)
        {
            await Task.Delay(5);
        }

        Assert.Equal(CaptureState.Finished, session.PollStats().CaptureState);
        session.Stop();
        var stats = session.PollStats();
        Assert.Equal(CaptureState.Idle, stats.CaptureState);
        Assert.Equal((ulong)SampleFrames, stats.Packets);
        Assert.Equal(0ul, stats.ParseErrors);
        Assert.Equal(10, session.PollTopFlows(10).Count);
        Assert.Empty(session.DrainAlerts());
    }

    [Fact]
    public void Native_errors_become_exceptions_with_messages()
    {
        using var session = new NetCoreSession();
        var noSource = Assert.Throws<NetCoreException>(session.Start);
        Assert.Equal(NcStatus.State, noSource.Status);
        Assert.Contains("no capture source", noSource.Message, StringComparison.Ordinal);

        var missing = Assert.Throws<NetCoreException>(() => session.OpenFile("does/not/exist.pcap"));
        Assert.Equal(NcStatus.Io, missing.Status);
        Assert.Contains("cannot open", missing.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Builtin_rules_raise_alerts_that_marshal_back()
    {
        using var session = new NetCoreSession();
        Assert.Equal(4, session.PollStats().RulesLoaded);

        for (ushort port = 1; port <= 120; port++)
        {
            session.Feed(port, TcpFrame(66, 50000, 5, port, 0x02));
        }

        var alert = Assert.Single(session.DrainAlerts());
        Assert.Equal("port-scan", alert.RuleId);
        Assert.Equal(AlertSeverity.High, alert.Severity);
        Assert.Equal(AlertSource.Rule, alert.Source);
        Assert.Equal(IPAddress.Parse("10.0.0.66"), alert.SourceAddress);
        Assert.StartsWith("10.0.0.66: 100 distinct ports", alert.Message, StringComparison.Ordinal);
        Assert.Equal(1.0, alert.Score);
    }

    [Fact]
    public void Rule_reload_reports_active_count_and_errors()
    {
        string good = Path.GetTempFileName();
        string bad = Path.GetTempFileName();
        try
        {
            File.WriteAllText(good, "version: 1\nrules:\n  - {id: a, kind: host_sweep, severity: low, window_secs: 5, threshold: 3}\n  - {id: b, kind: packet_rate, severity: low, window_secs: 1, threshold: 9, enabled: false}\n");
            File.WriteAllText(bad, "version: 7\nrules: []\n");
            using var session = new NetCoreSession();

            Assert.Equal(1, session.LoadRules(good));
            Assert.Equal(1, session.PollStats().RulesLoaded);
            var ex = Assert.Throws<NetCoreException>(() => session.LoadRules(bad));
            Assert.Equal(NcStatus.Rules, ex.Status);
            Assert.Contains("version 7", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(good);
            File.Delete(bad);
        }
    }

    [Fact]
    public void Analytics_link_reports_state_and_rejects_bad_endpoint()
    {
        using var session = new NetCoreSession();
        Assert.Equal(AnalyticsState.Off, session.PollStats().AnalyticsState);

        var ex = Assert.Throws<NetCoreException>(() => session.ConnectAnalytics("not a uri"));
        Assert.Equal(NcStatus.InvalidArg, ex.Status);

        session.ConnectAnalytics("http://127.0.0.1:1");
        Assert.Equal(AnalyticsState.Connecting, session.PollStats().AnalyticsState);
        session.DisconnectAnalytics();
        Assert.Equal(AnalyticsState.Off, session.PollStats().AnalyticsState);
    }

    [Fact]
    public void Dispose_is_idempotent_and_blocks_further_use()
    {
        var session = new NetCoreSession();
        session.Dispose();
        session.Dispose();
        Assert.Throws<ObjectDisposedException>(() => session.PollStats());
    }

    [Fact]
    public void Device_listing_works_or_reports_missing_library()
    {
        try
        {
            var devices = NetCoreSession.ListDevices();
            Assert.All(devices, d => Assert.False(string.IsNullOrEmpty(d.Name)));
        }
        catch (NetCoreException ex)
        {
            Assert.Contains(ex.Status, new[] { NcStatus.NoLibrary, NcStatus.Capture });
        }
    }

    [Fact]
    public void Poller_computes_rates_from_counter_deltas()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UnixEpoch);
        using var session = new NetCoreSession();
        var poller = new StatsPoller(session, time: time);

        var first = poller.PollOnce();
        Assert.Equal(default, first.Rate);

        session.Feed(1, TcpFrame(1, 1000, 2, 80, 0x10));
        session.Feed(2, TcpFrame(1, 1000, 2, 80, 0x10));
        time.Advance(TimeSpan.FromMilliseconds(500));
        var second = poller.PollOnce();

        Assert.Equal(4.0, second.Rate.PacketsPerSecond, 3);
        Assert.Equal(2 * 54 * 2.0, second.Rate.BytesPerSecond, 3);
        Assert.Single(second.TopFlows);
    }

    [Fact]
    public async Task Poller_raises_snapshots_on_its_own_thread()
    {
        using var session = new NetCoreSession();
        await using var poller = new StatsPoller(session, TimeSpan.FromMilliseconds(20));
        var received = new TaskCompletionSource<TrafficSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        poller.SnapshotReady += (_, s) => received.TrySetResult(s);

        session.Feed(1, TcpFrame(1, 1000, 2, 80, 0x10));
        poller.Start();
        var snapshot = await received.Task.WaitAsync(WaitLimit);
        await poller.StopAsync();

        Assert.Equal(1ul, snapshot.Stats.Packets);
        Assert.False(poller.IsRunning);
    }
}
