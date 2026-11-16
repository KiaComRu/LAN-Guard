using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using LanGuard.Shared;

namespace LanGuard.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        if (args is [var operation, var target] &&
            operation is "--read-inventory" or "--read-host-wmi" or "--read-host-shares")
        {
            if (target != "local" && (!IPAddress.TryParse(target, out var address) ||
                address.AddressFamily != AddressFamily.InterNetwork || address.ToString() != target ||
                !ScanNetwork.All().Any(network => network.Contains(address))))
            {
                Environment.ExitCode = 2;
                return;
            }
            var host = target == "local" ? null : target;
            object result = operation switch
            {
                "--read-host-wmi" => WindowsHostInventory.Read(host),
                "--read-host-shares" => NetworkShares.Read(host),
                _ => RegistryInventory.Read(host)
            };
            JsonSerializer.Serialize(Console.OpenStandardOutput(), result);
            return;
        }

        if (args.Length != 0)
            return;
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

    internal static SignatureCatalog ReadCatalog()
    {
        using var stream = typeof(Program).Assembly.GetManifestResourceStream("LanGuard.Signatures.json")!;
        return JsonSerializer.Deserialize<SignatureCatalog>(stream, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
    }
}
