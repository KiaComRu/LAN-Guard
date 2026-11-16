using System.Drawing;
using System.Net.NetworkInformation;
using System.Windows.Forms;

namespace LanGuard.Desktop;

internal sealed class MainForm : Form
{
    private static readonly Color Ink = Color.FromArgb(20, 35, 51);
    private static readonly Color Muted = Color.FromArgb(76, 93, 111);
    private static readonly Color Blue = Color.FromArgb(0, 95, 162);
    private static readonly Color Border = Color.FromArgb(223, 230, 236);
    private readonly Bitmap logo;
    private readonly ComboBox networks = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    private readonly TextBox range = new() { Dock = DockStyle.Fill, MaxLength = 24, AccessibleName = "Диапазон IPv4 в формате CIDR" };
    private readonly Button scan = new() { Text = "Сканировать" };
    private readonly Button stop = new() { Text = "Стоп", Enabled = false };
    private readonly Button import = new() { Text = "Загрузить имена из CSV…" };
    private readonly ComboBox mode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    private readonly Label coverage = Label("", 9, Muted);
    private readonly CheckBox matchesOnly = new() { Text = "Только с обнаружениями", AutoSize = true, Padding = new Padding(0, 4, 0, 0) };
    private readonly ProgressBar progress = new() { Dock = DockStyle.Fill, Minimum = 0, Maximum = 1 };
    private readonly Label summary = Label("Выберите локальную сеть и запустите проверку.", 10, Muted);
    private readonly DataGridView grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
        AllowUserToResizeRows = false, RowHeadersVisible = false, MultiSelect = false, BorderStyle = BorderStyle.None,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, BackgroundColor = Color.White, GridColor = Border,
        EnableHeadersVisualStyles = false, ColumnHeadersHeight = 38, AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None
    };
    private readonly TextBox detail = new()
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
        BackColor = Color.White, ForeColor = Ink, BorderStyle = BorderStyle.FixedSingle, AccessibleName = "Подробности проверки"
    };
    private readonly List<ScanResult> results = [];
    private ScanNetwork? resultNetwork;
    private DeviceNames? importedNames;
    private CancellationTokenSource? currentScan;
    private int completed;

    public MainForm()
    {
        Text = "LAN Guard — инвентаризация сети";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(780, 620);
        ClientSize = new Size(1070, 750);
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 10);
        BackColor = Color.FromArgb(242, 246, 249);
        ForeColor = Ink;
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);

        using var logoStream = typeof(MainForm).Assembly.GetManifestResourceStream("LanGuard.Logo.png")!;
        using var original = Image.FromStream(logoStream);
        logo = new Bitmap(original);
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1 };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 116));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, Margin = Padding.Empty, Padding = new Padding(22, 0, 22, 0),
            BackColor = Color.White, RowCount = 1, ColumnCount = 2
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 127));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.Controls.Add(new PictureBox
        {
            Image = logo, SizeMode = PictureBoxSizeMode.Zoom, Dock = DockStyle.Fill,
            Margin = new Padding(0, 0, 11, 0), AccessibleName = "Логотип LAN Guard"
        }, 0, 0);
        header.Controls.Add(Label("Поиск ПО удалённого управления", 18, Ink, bold: true), 1, 0);
        root.Controls.Add(header, 0, 0);

        var body = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 8, ColumnCount = 1, Padding = new Padding(19, 11, 19, 13) };
        foreach (var height in new[] { 60, 32, 35, 13 })
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
        body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        body.RowStyles.Add(new RowStyle(SizeType.Absolute, 33));
        body.RowStyles.Add(new RowStyle(SizeType.Absolute, 113));
        body.RowStyles.Add(new RowStyle(SizeType.Absolute, 29));
        root.Controls.Add(body, 0, 1);
        Controls.Add(root);

        var controls = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 4, Margin = Padding.Empty };
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 195));
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 132));
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        controls.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        controls.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        controls.Controls.Add(Label("Сетевой адаптер", 9, Muted, true), 0, 0);
        controls.Controls.Add(Label("Диапазон IPv4 (CIDR)", 9, Muted, true), 1, 0);
        controls.Controls.Add(networks, 0, 1);
        controls.Controls.Add(range, 1, 1);
        StyleButton(scan, Blue, Color.White);
        StyleButton(stop, Color.White, Ink);
        controls.Controls.Add(scan, 2, 1);
        controls.Controls.Add(stop, 3, 1);
        body.Controls.Add(controls, 0, 0);
        var modeRow = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 1, ColumnCount = 3, Margin = Padding.Empty };
        modeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 64));
        modeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 224));
        modeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        modeRow.Controls.Add(Label("Режим", 9, Muted, true), 0, 0);
        modeRow.Controls.Add(mode, 1, 0);
        modeRow.Controls.Add(coverage, 2, 0);
        body.Controls.Add(modeRow, 0, 1);

        var statusRow = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 1, ColumnCount = 2, Margin = Padding.Empty };
        statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        statusRow.Controls.Add(summary, 0, 0);
        statusRow.Controls.Add(matchesOnly, 1, 0);
        body.Controls.Add(statusRow, 0, 2);
        progress.Margin = new Padding(3, 0, 3, 5);
        body.Controls.Add(progress, 0, 3);
        ConfigureGrid();
        body.Controls.Add(grid, 0, 4);
        var detailHeader = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 1, ColumnCount = 2, Margin = Padding.Empty };
        detailHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        detailHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 227));
        detailHeader.Controls.Add(Label("Подробности проверки", 11, Ink, true), 0, 0);
        StyleButton(import, Color.White, Ink);
        detailHeader.Controls.Add(import, 1, 0);
        body.Controls.Add(detailHeader, 0, 5);
        body.Controls.Add(detail, 0, 6);
        var hint = Label("", 9, Muted);
        body.Controls.Add(hint, 0, 7);

        mode.AccessibleName = "Режим сканирования";
        mode.Items.AddRange(["Сетевые признаки", "Реестр Windows"]);
        mode.SelectedIndexChanged += (_, _) =>
        {
            coverage.Text = UseRegistry ? "Проверка с правами вашей учётной записи Windows." :
                "Проверка доступности портов без входа на удалённые ПК.";
            hint.Text = UseRegistry ? "Покрытие: записи установленных программ и загруженных профилей Windows." :
                "Открытый порт указывает на возможную службу. Установка программы остаётся неизвестной.";
            matchesOnly.Text = UseRegistry ? "Только с обнаружениями" : "Только с открытыми портами";
            grid.Columns[3].HeaderText = UseRegistry ? "Установленное ПО" : "Открытые порты · возможные службы";
            results.Clear();
            RefreshGrid();
            progress.Value = 0;
            summary.Text = "Выберите локальную сеть и запустите проверку.";
        };
        mode.SelectedIndex = 0;

        networks.AccessibleName = "Сетевой адаптер";
        networks.SelectedIndexChanged += (_, _) =>
        {
            if (networks.SelectedItem is ScanNetwork network)
                range.Text = network.DefaultRange;
        };
        matchesOnly.CheckedChanged += (_, _) => RefreshGrid();
        grid.SelectionChanged += (_, _) => ShowDetails();
        grid.CellContentClick += (_, cell) =>
        {
            if (cell.RowIndex < 0 || cell.ColumnIndex != 0 || resultNetwork is not { } network ||
                grid.Rows[cell.RowIndex].Tag is not ScanResult result)
                return;
            using var dialog = new HostDetailsForm(result, FindIdentity(result), network);
            dialog.ShowDialog(this);
        };
        import.Click += (_, _) => ImportNames();
        scan.Click += async (_, _) => await StartScan();
        stop.Click += (_, _) =>
        {
            stop.Enabled = false;
            currentScan?.Cancel();
        };
        FormClosing += (_, eventArgs) =>
        {
            if (currentScan is null)
                return;
            currentScan.Cancel();
            eventArgs.Cancel = true;
            closeAfterScan = true;
        };
        Shown += (_, _) => LoadNetworks();
    }

    private bool closeAfterScan;
    private bool UseRegistry => mode.SelectedIndex == 1;

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
            logo.Dispose();
    }

    private static Label Label(string text, float size, Color color, bool bold = false) => new()
    {
        Text = text, Font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular), ForeColor = color,
        Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true
    };

    private static void StyleButton(Button button, Color background, Color foreground)
    {
        button.Dock = DockStyle.Fill;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderColor = background == Color.White ? Border : background;
        button.BackColor = background;
        button.ForeColor = foreground;
        button.Font = new Font("Segoe UI", 10, FontStyle.Bold);
    }

    private void LoadNetworks()
    {
        try
        {
            networks.Items.AddRange(ScanNetwork.All());
            if (networks.Items.Count > 0)
                networks.SelectedIndex = 0;
            else
                summary.Text = "Активный сетевой адаптер с IPv4 не найден.";
        }
        catch (NetworkInformationException)
        {
            summary.Text = "Windows не предоставила сведения о сетевых адаптерах.";
        }
        scan.Enabled = networks.SelectedItem is ScanNetwork;
    }

    private async Task StartScan()
    {
        if (networks.SelectedItem is not ScanNetwork network || !network.TryGetTargets(range.Text, out var targets))
        {
            MessageBox.Show(this, "Введите подсеть выбранного адаптера в формате CIDR, например 192.168.1.0/24. " +
                "За один проход можно проверить диапазон до /22.", "Проверьте диапазон", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        results.Clear();
        resultNetwork = network;
        RefreshGrid();
        completed = 0;
        progress.Value = 0;
        progress.Maximum = targets.Length;
        scan.Enabled = networks.Enabled = range.Enabled = mode.Enabled = import.Enabled = false;
        stop.Enabled = true;
        using var cancellation = new CancellationTokenSource();
        currentScan = cancellation;
        UpdateSummary("Проверка");
        // Progress<T> posts to the UI context. The final marker drains the already queued reports.
        var drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var updates = new Progress<ScanProgress>(update =>
        {
            if (update.Completed == 0)
            {
                drained.SetResult();
                return;
            }
            completed += update.Completed;
            progress.Value = completed;
            if (update.Result is { } result)
            {
                results.Add(result);
                if (!matchesOnly.Checked || result.HasFinding)
                    AddRow(result);
            }
            UpdateSummary("Проверка");
        });
        var ending = "Завершено";
        try
        {
            await Scanner.Run(network, targets, UseRegistry, updates, cancellation.Token);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            ending = "Остановлено";
        }
        catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception
            or NetworkInformationException or InvalidOperationException or ArgumentException)
        {
            ending = "Ошибка проверки";
        }
        finally
        {
            ((IProgress<ScanProgress>)updates).Report(new ScanProgress(0, null));
            await drained.Task;
            currentScan = null;
            scan.Enabled = networks.Enabled = range.Enabled = mode.Enabled = import.Enabled = true;
            stop.Enabled = false;
            UpdateSummary(ending);
            if (closeAfterScan)
                Close();
        }
    }

    private void UpdateSummary(string phase)
    {
        var found = results.Count(result => result.HasFinding);
        var findingLabel = UseRegistry ? "с находками" : "с открытыми портами";
        var uncheckedCount = results.Count(result => result.Report?.Status != "checked");
        summary.Text = $"{phase} · {completed}/{progress.Maximum} адресов · {results.Count} устройств · " +
            $"{found} {findingLabel}" + (UseRegistry ? $" · {uncheckedCount} без полной проверки" : "");
    }

    private void ConfigureGrid()
    {
        grid.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(230, 238, 244), ForeColor = Ink };
        grid.DefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = Color.White, ForeColor = Ink, SelectionBackColor = Color.FromArgb(211, 236, 232), SelectionForeColor = Ink
        };
        grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(248, 250, 252);
        grid.RowTemplate.Height = 34;
        grid.Columns.Add(new DataGridViewLinkColumn
        {
            HeaderText = "IP", Width = 136, MinimumWidth = 75, SortMode = DataGridViewColumnSortMode.Automatic,
            LinkColor = Blue, ActiveLinkColor = Ink, TrackVisitedState = false,
            LinkBehavior = LinkBehavior.AlwaysUnderline
        });
        AddColumn("Компьютер", 160);
        AddColumn("Проверка", 161);
        AddColumn("Установленное ПО", 200, fill: true);
        AddColumn("Источник", 115);
    }

    private void AddColumn(string label, int width, bool fill = false) => grid.Columns.Add(new DataGridViewTextBoxColumn
    {
        HeaderText = label, Width = width, MinimumWidth = 75, AutoSizeMode = fill ?
            DataGridViewAutoSizeColumnMode.Fill : DataGridViewAutoSizeColumnMode.None,
        SortMode = DataGridViewColumnSortMode.Automatic
    });

    private void RefreshGrid()
    {
        grid.Rows.Clear();
        foreach (var result in results.Where(result => !matchesOnly.Checked || result.HasFinding)
                     .OrderBy(result => ScanNetwork.AddressNumber(result.Address)))
            AddRow(result);
        ShowDetails();
    }

    private void ImportNames()
    {
        using var dialog = new OpenFileDialog { Title = "Загрузить имена устройств", Filter = "Список устройств (*.csv)|*.csv" };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        try
        {
            var names = DeviceNames.Load(dialog.FileName);
            if (names.Count == 0)
                throw new InvalidDataException("В файле нет строк с именем и IP- или MAC-адресом.");
            importedNames = names;
            RefreshGrid();
            var matched = results.Count(result => result.Host is null && names.Find(result.Address, result.Mac) is not null);
            var feedback = results.Count == 0 ? "Имена будут подставлены при следующем сканировании." :
                $"Подставлено имён для текущих результатов: {matched}.";
            MessageBox.Show(this, $"Загружено записей: {names.Count}. {feedback}", "Имена устройств",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException
            or Microsoft.VisualBasic.FileIO.MalformedLineException)
        {
            MessageBox.Show(this, error.Message, "Не удалось загрузить имена", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private HostIdentity? FindIdentity(ScanResult result) =>
        result.Host ?? importedNames?.Find(result.Address, result.Mac);

    private void AddRow(ScanResult result)
    {
        var report = result.Report;
        var names = report is null
            ? string.Join(", ", result.Ports.Where(port => port.IsOpen).Select(port => $"{port.Port} · {port.PossibleService}"))
            : string.Join(", ", report.Matches.Select(match => match.ProductFamily));
        var status = report is null ? result.HasFinding ? "Есть признаки" : "Признаки не найдены" : StatusText(report.Status);
        var fallback = report is null ? "Проверенные порты недоступны" : report.Status == "checked" ? "Совпадений нет" : "Неизвестно";
        var host = FindIdentity(result);
        var index = grid.Rows.Add(result.Address.ToString(), host?.Name ?? "Не определено", status,
            names.Length > 0 ? names : fallback, result.Source);
        grid.Rows[index].Tag = result;
        grid.Rows[index].Cells[0].ToolTipText = "Открыть сведения об устройстве";
        grid.Rows[index].Cells[1].ToolTipText = host is null ? "" : $"{host.Name} · источник имени: {host.Source}";
        ShowDetails();
    }

    private void ShowDetails()
    {
        if (grid.CurrentRow?.Tag is not ScanResult result)
        {
            detail.Text = results.Count == 0 ? "Результаты появятся после запуска сканирования." : "Выберите устройство.";
            return;
        }
        var report = result.Report;
        var host = FindIdentity(result);
        var identity = (host is null ? "" : $"{host.Name}  •  ") + result.Address +
            (result.Mac is null ? "" : $"  •  MAC {result.Mac}");
        var nameSource = host is null ? "Сетевое имя не получено." : $"Источник имени: {host.Source}.";
        if (report is null)
        {
            detail.Lines = [identity, nameSource, .. result.Ports.Select(port => port.IsOpen
                ? $"TCP {port.Port} открыт · возможная служба: {port.PossibleService}"
                : $"TCP {port.Port} недоступен · {port.PossibleService}")];
            return;
        }
        var lines = new List<string>
        {
            $"{identity}  •  {StatusText(report.Status)}",
            nameSource,
            report.Message
        };
        foreach (var match in report.Matches)
        {
            lines.Add("");
            lines.Add($"{match.ProductFamily} · уверенность {(match.Confidence == "medium" ? "средняя" : "низкая")}");
            lines.AddRange(match.Evidence.Select(item =>
                string.Join(" · ", new[] { item.Observation.Name, item.Observation.Version, item.Observation.Publisher }
                    .Where(value => !string.IsNullOrWhiteSpace(value)))));
        }
        detail.Lines = [.. lines];
    }

    private static string StatusText(string status) => status switch
    {
        "checked" => "Проверен",
        "partial" => "Частичная проверка",
        _ => "Не проверен"
    };
}
