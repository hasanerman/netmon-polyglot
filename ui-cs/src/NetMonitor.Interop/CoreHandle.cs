using Microsoft.Win32.SafeHandles;

namespace NetMonitor.Interop;

internal sealed class CoreHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public CoreHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.Destroy(handle);
        return true;
    }
}
