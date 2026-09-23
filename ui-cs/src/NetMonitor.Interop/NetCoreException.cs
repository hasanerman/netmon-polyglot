namespace NetMonitor.Interop;

public sealed class NetCoreException : Exception
{
    public NetCoreException()
    {
    }

    public NetCoreException(string message)
        : base(message)
    {
    }

    public NetCoreException(string message, Exception inner)
        : base(message, inner)
    {
    }

    public NetCoreException(NcStatus status, string message)
        : base(message)
    {
        Status = status;
    }

    public NcStatus Status { get; }
}
