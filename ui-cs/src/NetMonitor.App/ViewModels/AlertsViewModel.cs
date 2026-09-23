using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetMonitor.Interop;

namespace NetMonitor.App.ViewModels;

public sealed partial class AlertsViewModel : ObservableObject
{
    public const int MaxAlerts = 500;

    public ObservableCollection<AlertRow> Items { get; } = [];

    [ObservableProperty]
    public partial int CriticalCount { get; set; }

    [ObservableProperty]
    public partial int HighCount { get; set; }

    [ObservableProperty]
    public partial int MediumCount { get; set; }

    [ObservableProperty]
    public partial int LowCount { get; set; }

    [ObservableProperty]
    public partial AlertRow? Selected { get; set; }

    public void Add(IEnumerable<AlertInfo> alerts)
    {
        ArgumentNullException.ThrowIfNull(alerts);
        foreach (var alert in alerts)
        {
            Items.Insert(0, AlertRow.From(alert));
            Count(alert.Severity, +1);
        }

        while (Items.Count > MaxAlerts)
        {
            var oldest = Items[^1];
            Items.RemoveAt(Items.Count - 1);
            Count(oldest.Level, -1);
        }
    }

    [RelayCommand]
    public void Clear()
    {
        Items.Clear();
        Selected = null;
        (CriticalCount, HighCount, MediumCount, LowCount) = (0, 0, 0, 0);
    }

    private void Count(AlertSeverity severity, int delta)
    {
        switch (severity)
        {
            case AlertSeverity.Critical:
                CriticalCount += delta;
                break;
            case AlertSeverity.High:
                HighCount += delta;
                break;
            case AlertSeverity.Medium:
                MediumCount += delta;
                break;
            default:
                LowCount += delta;
                break;
        }
    }
}
