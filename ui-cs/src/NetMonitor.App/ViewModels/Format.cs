using System.Globalization;

namespace NetMonitor.App.ViewModels;

internal static class Format
{
    private const double Kilo = 1024;
    private const double BitsPerByte = 8;
    private const double BitsPerMegabit = 1_000_000;
    private static readonly string[] ByteUnits = ["B", "KB", "MB", "GB", "TB"];

    public static string Bytes(double bytes)
    {
        int unit = 0;
        while (bytes >= Kilo && unit < ByteUnits.Length - 1)
        {
            bytes /= Kilo;
            unit++;
        }

        return unit == 0
            ? string.Create(CultureInfo.InvariantCulture, $"{bytes:0} {ByteUnits[unit]}")
            : string.Create(CultureInfo.InvariantCulture, $"{bytes:0.0} {ByteUnits[unit]}");
    }

    public static double Megabits(double bytesPerSecond) => bytesPerSecond * BitsPerByte / BitsPerMegabit;

    public static string Count(double value) => value.ToString("N0", CultureInfo.InvariantCulture);

    public static string Decimal(double value, int digits) =>
        value.ToString("F" + digits.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);

    public static string Seconds(TimeSpan span) =>
        string.Create(CultureInfo.InvariantCulture, $"{span.TotalSeconds:0.0} s");

    public static string LocalTime(DateTimeOffset time) =>
        time.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
}
