using System.ComponentModel;

namespace LanGuard.Desktop;

internal sealed record HostDetails(string Status, PortCheck[] Ports, ShareDetails? Shares, WmiDetails? Windows)
{
    public static HostDetails FromScan(string status) => new(status, [], null, null);
}

internal static class HostDetailsCollector
{
    private static readonly (int Port, string Service)[] Catalog =
    [
        (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"), (80, "HTTP"),
        (110, "POP3"), (135, "RPC / WMI"), (139, "NetBIOS"), (143, "IMAP"), (443, "HTTPS"), (445, "SMB"),
        (515, "LPD / печать"), (548, "AFP"), (587, "SMTP Submission"), (631, "IPP / печать"),
        (993, "IMAPS"), (995, "POP3S"), (1433, "SQL Server"), (2049, "NFS"), (3306, "MySQL"),
        (5432, "PostgreSQL"), (5985, "WinRM HTTP"), (5986, "WinRM HTTPS"), (8080, "HTTP"),
        (8443, "HTTPS"), (9100, "Печать RAW")
    ];

    internal static async Task<HostDetails> Collect(ScanNetwork network, ScanResult scan, CancellationToken ct)
    {
        if (!network.Contains(scan.Address))
            return HostDetails.FromScan("IP-адрес находится за пределами просканированной подсети.");

        var local = scan.Address.Equals(network.LocalIp);
        if (!local && scan.Mac is { } scannedMac)
        {
            var currentMac = await Task.Run(() => Scanner.ReadMac(network.LocalIp, scan.Address), ct);
            if (currentMac is not null && !currentMac.Equals(scannedMac, StringComparison.OrdinalIgnoreCase))
                return HostDetails.FromScan("MAC-адрес изменился. Запустите сканирование заново.");
        }

        var ports = new PortCheck[Catalog.Length];
        await Parallel.ForAsync(0, Catalog.Length, new ParallelOptions
        {
            MaxDegreeOfParallelism = 8, CancellationToken = ct
        }, async (index, token) =>
        {
            var (port, service) = Catalog[index];
            ports[index] = new PortCheck(port, service, await Scanner.IsOpen(network.LocalIp, scan.Address, port, token));
        });

        var target = local ? "local" : scan.Address.ToString();
        var shares = local || ports.Any(port => port.Port == 445 && port.IsOpen)
            ? Read<ShareDetails>("--read-host-shares", target, ct) : Task.FromResult<ShareDetails?>(null);
        var windows = local || ports.Any(port => port.Port == 135 && port.IsOpen)
            ? Read<WmiDetails>("--read-host-wmi", target, ct) : Task.FromResult<WmiDetails?>(null);
        await Task.WhenAll(shares, windows);
        return new HostDetails("Сбор завершён. Доступность источников указана на вкладках.", ports,
            await shares ?? new ShareDetails([], ports.Any(port => port.Port == 445 && port.IsOpen) || local
                ? "SMB не вернул список общих ресурсов." : "TCP 445 недоступен."),
            await windows ?? WindowsHostInventory.Unavailable(ports.Any(port => port.Port == 135 && port.IsOpen) || local
                ? "WMI не вернул данные за отведённое время." : "TCP 135 недоступен."));
    }

    private static async Task<T?> Read<T>(string operation, string target, CancellationToken ct) where T : class
    {
        try { return await Scanner.RunWorker<T>(operation, target, TimeSpan.FromSeconds(10), ct); }
        catch (Exception e) when (e is Win32Exception or IOException or InvalidOperationException) { return null; }
    }
}
