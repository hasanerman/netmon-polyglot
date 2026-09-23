namespace NetMonitor.Interop;

public sealed class StatsPoller : IAsyncDisposable
{
    public static readonly TimeSpan DefaultInterval = TimeSpan.FromMilliseconds(250);
    public const int DefaultTopFlows = 10;

    private readonly NetCoreSession _session;
    private readonly TimeSpan _interval;
    private readonly int _topFlows;
    private readonly TimeProvider _time;
    private readonly RateCalculator _rates = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public StatsPoller(NetCoreSession session, TimeSpan? interval = null, int topFlows = DefaultTopFlows, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        _session = session;
        _interval = interval ?? DefaultInterval;
        _topFlows = topFlows;
        _time = time ?? TimeProvider.System;
    }

    public event EventHandler<TrafficSnapshot>? SnapshotReady;

    public event EventHandler<Exception>? Faulted;

    public bool IsRunning => _loop is { IsCompleted: false };

    public TrafficSnapshot PollOnce()
    {
        var now = _time.GetUtcNow();
        var stats = _session.PollStats();
        return new TrafficSnapshot(
            stats,
            _session.PollTopFlows(_topFlows),
            _session.DrainAlerts(),
            _rates.Next(stats.Packets, stats.Bytes, now),
            now);
    }

    public void Start()
    {
        if (IsRunning)
        {
            return;
        }

        _rates.Reset();
        _cts = new CancellationTokenSource();
        _loop = RunAsync(_cts.Token);
    }

    public async Task StopAsync()
    {
        if (_cts is null || _loop is null)
        {
            return;
        }

        await _cts.CancelAsync().ConfigureAwait(false);
        try
        {
            await _loop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            _loop = null;
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);

    private async Task RunAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(_interval, _time);
        while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
        {
            try
            {
                SnapshotReady?.Invoke(this, PollOnce());
            }
            catch (NetCoreException ex)
            {
                Faulted?.Invoke(this, ex);
            }
        }
    }
}

internal sealed class RateCalculator
{
    private ulong _packets;
    private ulong _bytes;
    private DateTimeOffset? _at;

    public TrafficRate Next(ulong packets, ulong bytes, DateTimeOffset now)
    {
        var previous = _at;
        bool reset = packets < _packets || bytes < _bytes;
        (ulong dp, ulong db) = (packets - (reset ? 0 : _packets), bytes - (reset ? 0 : _bytes));
        (_packets, _bytes, _at) = (packets, bytes, now);

        if (previous is null || reset)
        {
            return default;
        }

        double seconds = (now - previous.Value).TotalSeconds;
        return seconds <= 0 ? default : new TrafficRate(dp / seconds, db / seconds);
    }

    public void Reset() => (_packets, _bytes, _at) = (0, 0, null);
}
