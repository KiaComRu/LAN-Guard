using System.Management;
using System.Runtime.InteropServices;

namespace LanGuard.Desktop;

internal sealed record InventorySection<T>(T[] Items, string Status);
internal sealed record AdapterDetails(string? Description, string? Mac, string[] Addresses, string[] Subnets,
    string[] Gateways, string[] Dns, bool UsesDhcp);
internal sealed record PrinterDetails(string? Name, string? Driver, string? Port, string? Share, bool IsNetwork);
internal sealed record ComputerDetails(string? Name, string? Manufacturer, string? Model);
internal sealed record OsDetails(string? Caption, string? Version, string? Build, string? Architecture);
internal sealed record WmiDetails(InventorySection<AdapterDetails> Adapters, InventorySection<PrinterDetails> Printers,
    InventorySection<ComputerDetails> Computer, InventorySection<OsDetails> Os);

internal static class WindowsHostInventory
{
    public static WmiDetails Read(string? target)
    {
        var scope = new ManagementScope(target is null ? @"\\.\root\cimv2" : $@"\\{target}\root\cimv2",
            new ConnectionOptions
            {
                Authentication = AuthenticationLevel.PacketPrivacy,
                Impersonation = ImpersonationLevel.Impersonate
            });
        try { scope.Connect(); }
        catch (Exception error) when (IsUnavailable(error)) { return Unavailable(Describe(error)); }

        return new WmiDetails(
            Query(scope, "SELECT Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled " +
                "FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE", 64,
                row => new AdapterDetails(GetText(row, "Description"), GetText(row, "MACAddress"),
                    GetList(row, "IPAddress"), GetList(row, "IPSubnet"), GetList(row, "DefaultIPGateway"),
                    GetList(row, "DNSServerSearchOrder"), row["DHCPEnabled"] is true)),
            Query(scope, "SELECT Name, DriverName, PortName, ShareName, Network FROM Win32_Printer", 128,
                row => new PrinterDetails(GetText(row, "Name"), GetText(row, "DriverName"),
                    GetText(row, "PortName"), GetText(row, "ShareName"), row["Network"] is true)),
            Query(scope, "SELECT Name, Manufacturer, Model FROM Win32_ComputerSystem", 1,
                row => new ComputerDetails(GetText(row, "Name"), GetText(row, "Manufacturer"), GetText(row, "Model"))),
            Query(scope, "SELECT Caption, Version, BuildNumber, OSArchitecture FROM Win32_OperatingSystem", 1,
                row => new OsDetails(GetText(row, "Caption"), GetText(row, "Version"),
                    GetText(row, "BuildNumber"), GetText(row, "OSArchitecture"))));
    }

    public static WmiDetails Unavailable(string status) =>
        new(new([], status), new([], status), new([], status), new([], status));

    private static InventorySection<T> Query<T>(ManagementScope scope, string query, int limit,
        Func<ManagementBaseObject, T> project)
    {
        var data = new List<T>();
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query),
                new System.Management.EnumerationOptions
                {
                    ReturnImmediately = true, Rewindable = false, Timeout = TimeSpan.FromSeconds(2)
                });
            using var rows = searcher.Get();
            foreach (ManagementBaseObject row in rows)
            {
                using (row)
                {
                    if (data.Count == limit)
                        return new InventorySection<T>([.. data], $"Показаны первые {limit} записей WMI.");
                    data.Add(project(row));
                }
            }
            return new InventorySection<T>([.. data], "Данные WMI получены.");
        }
        catch (Exception error) when (IsUnavailable(error))
        {
            return new InventorySection<T>([.. data], Describe(error));
        }
    }

    private static bool IsUnavailable(Exception error) =>
        error is ManagementException or COMException or UnauthorizedAccessException;

    private static string Describe(Exception error) => error is UnauthorizedAccessException ||
        error is ManagementException { ErrorCode: ManagementStatus.AccessDenied } || error.HResult == unchecked((int)0x80070005)
        ? "Отказано в доступе к WMI."
        : "Источник WMI недоступен или не ответил вовремя.";

    private static string? GetText(ManagementBaseObject row, string property) => NetworkShares.Clean(row[property] as string);
    private static string[] GetList(ManagementBaseObject row, string property) =>
        (row[property] as string[] ?? []).Take(32).Select(NetworkShares.Clean).OfType<string>().ToArray();
}
