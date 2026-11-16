using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace LanGuard.Desktop;

internal sealed record ScanResult(IPAddress Address, HostIdentity? Host, string? Mac, string Source,
    RegistryReport? Report, PortCheck[] Ports)
{
    public bool HasFinding => Report?.Matches.Length > 0 || Ports.Any(port => port.IsOpen);
}
internal sealed record ScanProgress(int Completed, ScanResult? Result);
internal sealed record PortCheck(int Port, string PossibleService, bool IsOpen);

internal static partial class Scanner
{
    private static readonly (int Port, string Service)[] RemoteAccessPorts =
    [
        (3389, "RDP"), (5900, "VNC"), (5931, "Ammyy Admin"), (5938, "TeamViewer"),
        (7070, "AnyDesk"), (21115, "RuDesktop")
    ];

    public static Task Run(ScanNetwork network, IPAddress[] addresses, bool readRegistry, IProgress<ScanProgress> progress,
        CancellationToken cancellationToken)
    {
        if (addresses.Length is < 1 or > 1024 || addresses.Any(address => !network.Contains(address)))
            throw new ArgumentException("Диапазон выходит за границы выбранной сети.");

        return Parallel.ForEachAsync(addresses, new ParallelOptions
        {
            MaxDegreeOfParallelism = 16,
            CancellationToken = cancellationToken
        }, async (address, ct) =>
        {
            ScanResult? result = null;
            try
            {
                result = await Scan(network, address, readRegistry, ct);
            }
            finally
            {
                progress.Report(new ScanProgress(1, result));
            }
        });
    }

    private static async Task<ScanResult?> Scan(ScanNetwork network, IPAddress address, bool readRegistry, CancellationToken ct)
    {
        if (address.Equals(network.LocalIp))
            return new ScanResult(address, new HostIdentity(Environment.MachineName, "Этот компьютер"), null, "Этот компьютер",
                readRegistry ? await ReadRegistry("local", ct) : null,
                readRegistry ? [] : await ProbePorts(network.LocalIp, address, ct));

        ct.ThrowIfCancellationRequested();
        var arp = Task.Run(() => ReadMac(network.LocalIp, address), ct);
        var ping = PingHost(address, ct);
        var smb = readRegistry ? IsOpen(network.LocalIp, address, 445, ct) : Task.FromResult(false);
        var probes = readRegistry ? Task.FromResult(Array.Empty<PortCheck>()) : ProbePorts(network.LocalIp, address, ct);
        await Task.WhenAll(arp, ping, smb, probes);
        ct.ThrowIfCancellationRequested();
        var mac = await arp;
        var replies = await ping;
        var hasSmb = await smb;
        var ports = await probes;
        if (mac is null && !replies && !hasSmb && !ports.Any(port => port.IsOpen))
            return null;

        var source = mac is not null ? "ARP" : replies ? "ICMP" : hasSmb ? "SMB" : "TCP";
        var report = !readRegistry ? null : hasSmb ? await ReadRegistry(address.ToString(), ct)
            : Unavailable("Служба SMB (TCP 445) недоступна. Реестр не проверен.");
        var host = report?.Hostname is { } hostname ? new HostIdentity(hostname, "реестр Windows") :
            await HostNames.Resolve(network.LocalIp, address, ct);
        return new ScanResult(address, host, mac, source, report, ports);
    }

    internal static Task<PortCheck[]> ProbePorts(IPAddress local, IPAddress target, CancellationToken ct) =>
        Task.WhenAll(RemoteAccessPorts.Select(async item =>
            new PortCheck(item.Port, item.Service, await IsOpen(local, target, item.Port, ct))));

    internal static async Task<RegistryReport> ReadRegistry(string target, CancellationToken ct) =>
        await RunWorker<RegistryReport>("--read-inventory", target, TimeSpan.FromSeconds(12), ct)
        ?? Unavailable("Реестр недоступен или время ожидания ответа истекло.");

    internal static async Task<T?> RunWorker<T>(string operation, string target, TimeSpan timeout,
        CancellationToken ct) where T : class
    {
        ct.ThrowIfCancellationRequested();
        var start = new ProcessStartInfo(Environment.ProcessPath!)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add(operation);
        start.ArgumentList.Add(target);
        using var reader = Process.Start(start) ?? throw new InvalidOperationException("Не удалось запустить сбор сведений.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        var output = reader.StandardOutput.ReadToEndAsync(deadline.Token);
        try
        {
            await reader.WaitForExitAsync(deadline.Token);
            var json = await output;
            return reader.ExitCode == 0 ? JsonSerializer.Deserialize<T>(json) : null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
        finally
        {
            if (!reader.HasExited)
            {
                try { reader.Kill(); }
                catch (InvalidOperationException) when (reader.HasExited) { }
                await reader.WaitForExitAsync();
            }
            try { await output; }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        }
    }

    private static RegistryReport Unavailable(string reason) => new(null, "unavailable", reason, []);

    internal static async Task<bool> IsOpen(IPAddress local, IPAddress target, int port, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromMilliseconds(650));
        try
        {
            using var connection = new TcpClient(new IPEndPoint(local, 0));
            await connection.ConnectAsync(target, port, deadline.Token);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
    }

    private static async Task<bool> PingHost(IPAddress address, CancellationToken ct)
    {
        using var ping = new Ping();
        try
        {
            return (await ping.SendPingAsync(address, TimeSpan.FromMilliseconds(650), cancellationToken: ct))
                .Status == IPStatus.Success;
        }
        catch (PingException)
        {
            return false;
        }
    }

    internal static string? ReadMac(IPAddress source, IPAddress destination)
    {
        Span<byte> bytes = stackalloc byte[8];
        uint length = (uint)bytes.Length;
        var status = SendARP(BitConverter.ToUInt32(destination.GetAddressBytes()),
            BitConverter.ToUInt32(source.GetAddressBytes()), ref MemoryMarshal.GetReference(bytes), ref length);
        return status == 0 && length is > 0 and <= 8
            ? string.Join(":", bytes[..(int)length].ToArray().Select(value => value.ToString("X2")))
            : null;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint SendARP(uint destination, uint source, ref byte mac, ref uint length);
}
