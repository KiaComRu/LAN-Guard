using System.Net;
using System.Text.Json;
using LanGuard.Agent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("LAN Guard Agent requires Windows.");

if (args is ["--inventory-only"])
{
    var inventory = new WindowsInventory().Collect(CancellationToken.None);
    Console.WriteLine(JsonSerializer.Serialize(inventory.Coverage, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    return;
}

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    ContentRootPath = AppContext.BaseDirectory
});
var statePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LanGuard");
builder.Configuration.AddJsonFile(Path.Combine(statePath, "agent.json"), optional: false);
var options = builder.Configuration.GetSection("Agent").Get<AgentOptions>()
    ?? throw new InvalidOperationException("Agent settings are missing.");
if (!Uri.TryCreate(options.Server, UriKind.Absolute, out var server) || server.Scheme != "https" ||
    server.AbsolutePath != "/" || server.Query.Length > 0 || server.Fragment.Length > 0 || server.UserInfo.Length > 0 ||
    options.HeartbeatSeconds is < 15 or > 60 || options.ScanMinutes is < 1 or > 10080 ||
    options.RotationDays is < 1 or > 365)
    throw new InvalidOperationException("Agent requires an HTTPS origin and valid schedule settings.");

builder.Services.AddWindowsService(options => options.ServiceName = "LanGuardAgent");
builder.Services.AddSingleton(options);
builder.Services.AddSingleton(new AgentStore(statePath));
builder.Services.AddSingleton<IEndpointInventoryProvider, WindowsInventory>();
builder.Services.AddSingleton(new HttpClient(new HttpClientHandler
{
    AllowAutoRedirect = false,
    AutomaticDecompression = DecompressionMethods.All
})
{
    BaseAddress = new Uri(server.GetLeftPart(UriPartial.Authority) + "/api/v1/agents/"),
    Timeout = TimeSpan.FromSeconds(15)
});
builder.Services.AddHostedService<AgentWorker>();
await builder.Build().RunAsync();

public sealed class AgentOptions
{
    public string Server { get; init; } = "";
    public int HeartbeatSeconds { get; init; } = 30;
    public int ScanMinutes { get; init; } = 720;
    public int RotationDays { get; init; } = 30;
}
