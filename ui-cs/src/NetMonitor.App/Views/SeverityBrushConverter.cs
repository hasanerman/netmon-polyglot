using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using NetMonitor.App.ViewModels;
using NetMonitor.Interop;

namespace NetMonitor.App.Views;

public sealed class SeverityBrushConverter : IValueConverter
{
    public static readonly SeverityBrushConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not AlertSeverity severity)
        {
            return Brushes.Transparent;
        }

        var c = MainViewModel.SeverityColor(severity);
        return new SolidColorBrush(Color.FromArgb(c.Alpha, c.Red, c.Green, c.Blue));
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
