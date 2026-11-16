using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using LanGuard.Server;
using LanGuard.Shared;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace LanGuard.Tests;

public sealed class ApiTests
{
    private const string Password = "Local tests only, 9f7a!";

    [Fact]
    public async Task DemoHasOnlyFixturesAndRequiresAuthentication()
    {
        using var app = new GuardFactory(demo: true);
        using var client = Client(app);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/healthz")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/devices")).StatusCode);
        await Login(client);

        var overview = await Get(client, "/api/v1/overview");
        Assert.True(overview.GetProperty("demo").GetBoolean());
        Assert.Equal(4, overview.GetProperty("devices").GetInt32());
        var rows = await Get(client, "/api/v1/devices");
        Assert.Contains(rows.GetProperty("items").EnumerateArray(),
            row => row.GetProperty("result").GetString() == "not_scanned" && !row.GetProperty("hasAgent").GetBoolean());
        Assert.Contains(rows.GetProperty("items").EnumerateArray(),
            row => row.GetProperty("result").GetString() == "unknown");
        var detections = await Get(client, "/api/v1/detections?family=anydesk");
        Assert.Equal(1, detections.GetProperty("total").GetInt32());
        Assert.Contains("AnyDesk", await client.GetStringAsync("/api/v1/reports/detections.csv"));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/openapi/v1.json")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await AdminPost(client, "enrollment-tokens", new { })).StatusCode);
    }

    [Fact]
    public async Task AgentEnrollsOnceRotatesAndReportsIdempotently()
    {
        using var app = new GuardFactory(demo: false);
        using var admin = Client(app);
        using var agent = Client(app);
        await Login(admin);
        var missingCsrf = await admin.PostAsJsonAsync("/api/v1/enrollment-tokens", new { });
        Assert.Equal(HttpStatusCode.BadRequest, missingCsrf.StatusCode);
        var issued = await AdminPost(admin, "enrollment-tokens", new { });
        var token = (await issued.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;
        var id = Guid.NewGuid();
        var secret = Secrets.Create();
        var enrollment = new Enrollment(1, id, token, secret);
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "enroll", enrollment));
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "enroll", enrollment));
        Assert.Equal(HttpStatusCode.Unauthorized, await AgentPost(agent, "enroll", enrollment with { AgentId = Guid.NewGuid() }));

        var heartbeat = new Heartbeat(1, "TEST-AGENT", "Windows 11", "1.0.0", ["192.0.2.42"],
            Protocol.RequiredSources, "not_scanned");
        Assert.Equal(HttpStatusCode.Unauthorized, await AgentPost(agent, "heartbeat", heartbeat));
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", $"{id:D}.{secret}");
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "heartbeat", heartbeat));
        var replacement = Secrets.Create();
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "rotate", new Rotation(1, replacement)));
        Assert.Equal(HttpStatusCode.Unauthorized, await AgentPost(agent, "heartbeat", heartbeat));
        agent.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", $"{id:D}.{replacement}");
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "heartbeat", heartbeat));
        Assert.Equal(HttpStatusCode.Unauthorized, (await agent.GetAsync("/api/v1/devices")).StatusCode);

        var coverage = Protocol.RequiredSources.Select(x => new Coverage(x, "complete", 1)).ToArray();
        var inventory = new Inventory(1, Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-2), coverage,
            [new Observation("process", "portable", OriginalFilename: "RustDesk.exe", Product: "RustDesk")]);
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "inventory", inventory));
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "inventory", inventory));
        Assert.Equal(2, (await Get(admin, "/api/v1/events")).GetArrayLength());

        var partial = inventory with
        {
            ScanId = Guid.NewGuid(), ScannedAt = inventory.ScannedAt.AddSeconds(10), Observations = [],
            Coverage = [.. coverage.Where(x => x.Source != "processes"), new("processes", "partial", 0, "Access denied")]
        };
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "inventory", partial));
        var detail = await Get(admin, $"/api/v1/devices/{id:D}");
        var device = detail.GetProperty("device");
        Assert.Equal("partial_scan", device.GetProperty("auditStatus").GetString());
        Assert.Equal(JsonValueKind.Null, device.GetProperty("detections")[0].GetProperty("currentlyRunning").ValueKind);

        var empty = inventory with { ScanId = Guid.NewGuid(), ScannedAt = inventory.ScannedAt.AddSeconds(20), Observations = [] };
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "inventory", empty));
        Assert.Equal(HttpStatusCode.NoContent, await AgentPost(agent, "inventory", inventory with { ScanId = Guid.NewGuid() }));
        detail = await Get(admin, $"/api/v1/devices/{id:D}");
        Assert.Equal("not_detected", detail.GetProperty("device").GetProperty("result").GetString());
        Assert.Equal(4, (await Get(admin, "/api/v1/events")).GetArrayLength());
    }

    private static HttpClient Client(GuardFactory app) => app.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false
    });

    private static async Task Login(HttpClient client)
    {
        var response = await AdminPost(client, "auth/login", new { login = "admin", password = Password });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private static async Task<HttpResponseMessage> AdminPost(HttpClient client, string path, object data)
    {
        var csrf = await Get(client, "/api/v1/auth/csrf");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/" + path)
        {
            Content = JsonContent.Create(data)
        };
        request.Headers.Add("X-CSRF-Token", csrf.GetProperty("token").GetString());
        return await client.SendAsync(request);
    }

    private static async Task<JsonElement> Get(HttpClient client, string path) =>
        await client.GetFromJsonAsync<JsonElement>(path);

    private static async Task<HttpStatusCode> AgentPost<T>(HttpClient client, string path, T input)
    {
        using var response = await client.PostAsJsonAsync("/api/v1/agents/" + path, input);
        return response.StatusCode;
    }

    private sealed class GuardFactory(bool demo) : WebApplicationFactory<Program>
    {
        private readonly string data = Path.Combine(Path.GetTempPath(), "languard-tests-" + Guid.NewGuid().ToString("N"));

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.ConfigureHostConfiguration(config => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["LanGuard:Demo"] = demo.ToString(), ["LanGuard:AdminPassword"] = Password, ["LanGuard:DataPath"] = data
            }));
            return base.CreateHost(builder);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing && Directory.Exists(data))
            {
                Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                Directory.Delete(data, recursive: true);
            }
        }
    }
}
