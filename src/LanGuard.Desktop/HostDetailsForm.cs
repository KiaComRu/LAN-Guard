using System.Drawing;
using System.Windows.Forms;

namespace LanGuard.Desktop;

internal sealed class HostDetailsForm : Form
{
    private readonly TextBox overview;
    private readonly TextBox ports;
    private readonly TextBox adapters;
    private readonly TextBox resources;
    private readonly Label status;
    private readonly ScanResult scan;
    private readonly HostIdentity? identity;
    private readonly ScanNetwork network;

    public HostDetailsForm(ScanResult scan, HostIdentity? identity, ScanNetwork network)
    {
        this.scan = scan;
        this.identity = identity;
        this.network = network;
        Text = $"Сведения об устройстве · {scan.Address}";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        MinimumSize = new Size(685, 465);
        ClientSize = new Size(785, 535);
        Font = new Font("Segoe UI", 10);
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        BackColor = Color.FromArgb(242, 246, 249);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, Padding = new Padding(14), RowCount = 4, ColumnCount = 1
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 37));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
        var heading = new Label
        {
            Dock = DockStyle.Fill, AutoEllipsis = true,
            Text = identity is null ? scan.Address.ToString() : $"{identity.Name}  ·  {scan.Address}",
            Font = new Font("Segoe UI", 17, FontStyle.Bold), ForeColor = Color.FromArgb(20, 35, 51)
        };
        status = new Label { Dock = DockStyle.Fill, AutoEllipsis = true, ForeColor = Color.FromArgb(76, 93, 111) };
        var tabs = new TabControl { Dock = DockStyle.Fill };
        overview = AddTab(tabs, "Общее");
        ports = AddTab(tabs, "Порты");
        adapters = AddTab(tabs, "Сетевые адаптеры");
        resources = AddTab(tabs, "Папки и принтеры");
        var close = new Button { Text = "Закрыть", DialogResult = DialogResult.Cancel, Anchor = AnchorStyles.Right, Width = 112, Height = 31 };
        CancelButton = close;
        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(status, 0, 1);
        layout.Controls.Add(tabs, 0, 2);
        layout.Controls.Add(close, 0, 3);
        Controls.Add(layout);

        ShowDetails(HostDetails.FromScan("Получаем дополнительные сведения…"));
        Shown += async (_, _) => await Collect();
    }

    private async Task Collect()
    {
        using var cancellation = new CancellationTokenSource();
        FormClosedEventHandler cancel = (_, _) => cancellation.Cancel();
        FormClosed += cancel;
        try
        {
            var details = await HostDetailsCollector.Collect(network, scan, cancellation.Token);
            if (!IsDisposed && !cancellation.IsCancellationRequested)
                ShowDetails(details);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        finally { FormClosed -= cancel; }
    }

    private static TextBox AddTab(TabControl tabs, string title)
    {
        var box = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
            BackColor = Color.White, BorderStyle = BorderStyle.None, AccessibleName = title
        };
        var tab = new TabPage(title) { Padding = new Padding(12), BackColor = Color.White };
        tab.Controls.Add(box);
        tabs.TabPages.Add(tab);
        return box;
    }

    private void ShowDetails(HostDetails details)
    {
        status.Text = details.Status;
        var summary = new List<string>
        {
            $"IP-адрес: {scan.Address}",
            $"Сетевое имя: {identity?.Name ?? "Не определено"}",
            $"Источник имени: {identity?.Source ?? "—"}",
            $"MAC-адрес в сети: {scan.Mac ?? "Не определён"}",
            $"Обнаружено через: {scan.Source}",
            $"Адаптер сканирования: {network.Adapter} ({network.LocalIp})"
        };
        if (details.Windows is { } win)
        {
            summary.Add("");
            summary.Add(Section("Компьютер", win.Computer.Status, win.Computer.Items.Select(pc =>
                string.Join("\r\n", $"Имя Windows: {pc.Name ?? "—"}", $"Производитель: {pc.Manufacturer ?? "—"}", $"Модель: {pc.Model ?? "—"}"))));
            summary.Add(Section("Операционная система", win.Os.Status, win.Os.Items.Select(os =>
                $"{os.Caption ?? "—"} · {os.Version ?? "—"} · сборка {os.Build ?? "—"} · {os.Architecture ?? "—"}")));
        }
        overview.Lines = [.. summary];

        var extraOpen = details.Ports.Where(port => port.IsOpen).Select(PortLabel);
        var extraStatus = details.Ports.Length == 0 ? "Дополнительные порты не проверялись." :
            $"Проверено дополнительных TCP-портов: {details.Ports.Length}.";
        ports.Text = Section("Сетевые признаки при основном сканировании", "",
            scan.Ports.Where(port => port.IsOpen).Select(PortLabel)) + "\r\n\r\n" +
            Section("Дополнительные открытые порты", extraStatus, extraOpen) +
            "\r\n\r\nНазначение службы предполагается по номеру порта.";

        adapters.Text = details.Windows is { } machine
            ? Section("Сетевые адаптеры с включённым TCP/IP", machine.Adapters.Status, machine.Adapters.Items.Select(adapter =>
                string.Join("\r\n",
                    adapter.Description ?? "Сетевой адаптер", $"    MAC: {adapter.Mac ?? "—"}",
                    $"    IP: {Values(adapter.Addresses)}", $"    Маски / префиксы: {Values(adapter.Subnets)}",
                    $"    Шлюзы: {Values(adapter.Gateways)}", $"    DNS: {Values(adapter.Dns)}",
                    $"    DHCP: {(adapter.UsesDhcp ? "включён" : "выключен")}")))
            : details.Status;

        var shareSection = details.Shares is { } shares
            ? Section("Общие папки и очереди печати SMB", shares.Status, shares.Items.Select(share =>
                $@"{share.Kind}: \\{scan.Address}\{share.Name}" + (share.Hidden ? " · скрытый ресурс" : "") +
                (share.Description is null ? "" : $" · {share.Description}")))
            : details.Status;
        if (details.Windows is { } windows)
            shareSection += "\r\n\r\n" + Section("Принтеры, видимые через WMI", windows.Printers.Status,
                windows.Printers.Items.Select(printer =>
                    $"{printer.Name ?? "Принтер"} · {(printer.IsNetwork ? "сетевой" : "локальный")} · порт {printer.Port ?? "—"}" +
                    (printer.Driver is null ? "" : $" · {printer.Driver}") +
                    (printer.Share is null ? "" : $" · общий ресурс {printer.Share}")));
        resources.Text = shareSection;
    }

    private static string PortLabel(PortCheck port) => $"TCP {port.Port} · {port.PossibleService}";
    private static string Values(string[] values) => values.Length == 0 ? "—" : string.Join(", ", values);

    private static string Section(string title, string message, IEnumerable<string> entries)
    {
        var lines = entries.ToArray();
        var list = lines.Length == 0 ? "Нет записей для отображения." : string.Join("\r\n", lines);
        return $"{title}\r\n" + (message.Length == 0 ? "" : $"{message}\r\n") + list;
    }
}
