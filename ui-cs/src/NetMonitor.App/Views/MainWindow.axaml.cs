using Avalonia.Controls;
using Avalonia.Platform.Storage;
using NetMonitor.App.ViewModels;

namespace NetMonitor.App.Views;

public partial class MainWindow : Window
{
    private static readonly FilePickerFileType PcapFiles = new("Packet capture") { Patterns = ["*.pcap"] };
    private static readonly FilePickerFileType RuleFiles = new("Rule file") { Patterns = ["*.yaml", "*.yml"] };

    public MainWindow()
    {
        InitializeComponent();
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is MainViewModel vm)
        {
            vm.PickCaptureFile = () => PickFileAsync("Open capture file", PcapFiles);
            vm.PickRulesFile = () => PickFileAsync("Load rules", RuleFiles);
        }
    }

    private async Task<string?> PickFileAsync(string title, FilePickerFileType type)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = [type, FilePickerFileTypes.All],
        });
        return files.Count == 0 ? null : files[0].TryGetLocalPath();
    }
}
