using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using LanGuard.Shared;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LanGuard.Agent;

[SupportedOSPlatform("windows")]
public sealed class AgentWorker(AgentStore store, AgentOptions options, HttpClient http,
    IEndpointInventoryProvider inventory, ILogger<AgentWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var identity = store.LoadOrCreate();
        var nextScan = DateTimeOffset.MinValue;
        var nextContact = DateTimeOffset.MinValue;
        var failures = 0;
        var lastScanStatus = "not_scanned";

        while (!stoppingToken.IsCancellationRequested)
        {
            if (DateTimeOffset.UtcNow >= nextScan)
            {
                var report = inventory.Collect(stoppingToken);
                lastScanStatus = report.Coverage.All(source => source.Status == "complete") ? "scanned" : "partial_scan";
                if (store.Queue(report))
                    nextScan = DateTimeOffset.UtcNow.AddMinutes(options.ScanMinutes);
                else
                {
                    logger.LogWarning("Очередь инвентаризации заполнена. Следующая попытка через минуту.");
                    nextScan = DateTimeOffset.UtcNow.AddMinutes(1);
                }
            }

            if (DateTimeOffset.UtcNow >= nextContact)
            {
                try
                {
                    identity = await EnsureIdentity(identity, stoppingToken);
                    await SendHeartbeat(identity, lastScanStatus, stoppingToken);
                    foreach (var file in store.Pending().Take(5))
                    {
                        using var body = new StreamContent(file.OpenRead());
                        body.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                        using var response = await Send("inventory", body, identity, stoppingToken);
                        if (response.StatusCode == HttpStatusCode.BadRequest)
                        {
                            logger.LogWarning("Сервер отклонил отчёт. Он сохранён в папке очереди с расширением .rejected.");
                            body.Dispose();
                            file.MoveTo(Path.ChangeExtension(file.FullName, ".rejected"));
                            continue;
                        }
                        response.EnsureSuccessStatusCode();
                        body.Dispose();
                        file.Delete();
                    }
                    failures = 0;
                    nextContact = DateTimeOffset.UtcNow.AddSeconds(options.HeartbeatSeconds);
                }
                catch (Exception error) when (error is HttpRequestException ||
                    error is OperationCanceledException && !stoppingToken.IsCancellationRequested)
                {
                    // Reload the durable rotation/enrollment state after an interrupted response.
                    identity = store.LoadOrCreate();
                    failures = Math.Min(failures + 1, 5);
                    var seconds = Math.Min(120, 5 * (1 << failures)) + Random.Shared.Next(0, 5);
                    nextContact = DateTimeOffset.UtcNow.AddSeconds(seconds);
                    logger.LogWarning("Синхронизация недоступна ({Status}). Повтор через {Seconds} с.",
                        (error as HttpRequestException)?.StatusCode?.ToString() ?? "transport", seconds);
                }
            }

            var next = nextScan < nextContact ? nextScan : nextContact;
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(100, (next - DateTimeOffset.UtcNow).TotalMilliseconds)),
                stoppingToken);
        }
    }

    private async Task<AgentIdentity> EnsureIdentity(AgentIdentity identity, CancellationToken ct)
    {
        if (!identity.Enrolled)
        {
            using var response = await Send("enroll", JsonContent.Create(new Enrollment(
                Protocol.Version, identity.Id, store.ReadToken(), identity.Credential)), null, ct);
            response.EnsureSuccessStatusCode();
            identity = identity with { Enrolled = true, RotatedAt = DateTimeOffset.UtcNow };
            store.Save(identity);
        }
        store.RemoveToken();

        if (identity.PendingCredential is null && identity.RotatedAt.AddDays(options.RotationDays) > DateTimeOffset.UtcNow)
            return identity;
        if (identity.PendingCredential is null)
        {
            identity = identity with { PendingCredential = AgentStore.CreateSecret() };
            store.Save(identity);
        }
        var pending = identity.PendingCredential!;
        using var rotation = await Send("rotate", JsonContent.Create(new Rotation(Protocol.Version, pending)), identity, ct);
        if (rotation.StatusCode == HttpStatusCode.Unauthorized)
        {
            using var confirmation = await Send("rotate", JsonContent.Create(new Rotation(Protocol.Version, pending)),
                identity with { Credential = pending }, ct);
            confirmation.EnsureSuccessStatusCode();
        }
        else
        {
            rotation.EnsureSuccessStatusCode();
        }
        identity = identity with { Credential = pending, PendingCredential = null, RotatedAt = DateTimeOffset.UtcNow };
        store.Save(identity);
        return identity;
    }

    private async Task SendHeartbeat(AgentIdentity identity, string status, CancellationToken ct)
    {
        var addresses = NetworkInterface.GetAllNetworkInterfaces()
            .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up)
            .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
            .Select(item => item.Address).Where(address => !IPAddress.IsLoopback(address))
            .Select(address => address.ToString()).Distinct().Take(32).ToArray();
        var version = typeof(AgentWorker).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        using var response = await Send("heartbeat", JsonContent.Create(new Heartbeat(Protocol.Version,
            Environment.MachineName, RuntimeInformation.OSDescription, version, addresses, WindowsInventory.Capabilities,
            status)), identity, ct);
        response.EnsureSuccessStatusCode();
    }

    private async Task<HttpResponseMessage> Send(string route, HttpContent body, AgentIdentity? identity, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, route) { Content = body };
        if (identity is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", $"{identity.Id:D}.{identity.Credential}");
        return await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
    }
}
