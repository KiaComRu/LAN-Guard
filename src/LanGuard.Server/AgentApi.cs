using System.Net;
using System.Security.Cryptography;
using LanGuard.Shared;
using Microsoft.EntityFrameworkCore;

namespace LanGuard.Server;

public static class AgentApi
{
    public static void MapAgentApi(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/agents");
        group.AddEndpointFilter(async (context, next) =>
            context.HttpContext.RequestServices.GetRequiredService<ServerMode>().Demo
                ? Results.NotFound()
                : await next(context));
        group.MapPost("/enroll", Enroll).RequireRateLimiting("auth");
        group.MapPost("/heartbeat", Heartbeat);
        group.MapPost("/inventory", Inventory);
        group.MapPost("/rotate", Rotate);
    }

    private static async Task<IResult> Enroll(Enrollment input, GuardDb db, CancellationToken ct)
    {
        if (input.ProtocolVersion != Protocol.Version || input.AgentId == Guid.Empty ||
            !Secrets.Valid(input.Token) || !Secrets.Valid(input.Credential))
            return Results.BadRequest();

        var existing = await db.Devices.FindAsync([input.AgentId], ct);
        if (existing is not null)
            return Secrets.Matches(input.Credential, existing.CredentialHash)
                ? Results.NoContent()
                : Results.Conflict();

        var token = await db.EnrollmentTokens.FindAsync([Secrets.Hash(input.Token)], ct);
        if (token is null || token.UsedAt is not null || token.ExpiresAt <= Storage.Now)
            return Results.Unauthorized();

        token.UsedAt = Storage.Now;
        db.Devices.Add(new Device { Id = input.AgentId, CredentialHash = Secrets.Hash(input.Credential) });
        try
        {
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }
        catch (DbUpdateException)
        {
            // A competing enrollment can consume the same token while this request is in flight.
            db.ChangeTracker.Clear();
            existing = await db.Devices.FindAsync([input.AgentId], ct);
            if (existing is not null && Secrets.Matches(input.Credential, existing.CredentialHash))
                return Results.NoContent();
            var current = await db.EnrollmentTokens.FindAsync([Secrets.Hash(input.Token)], ct);
            if (current?.UsedAt is not null || existing is not null)
                return Results.Conflict();
            throw;
        }
    }

    private static async Task<IResult> Heartbeat(Heartbeat input, HttpContext context, GuardDb db, CancellationToken ct)
    {
        var device = await Authenticate(context, db, ct);
        if (device is null)
            return Results.Unauthorized();
        if (input.ProtocolVersion != Protocol.Version || !Required(input.Hostname, 255) ||
            !Required(input.Os, 200) || !Required(input.AgentVersion, 40) ||
            input.Addresses is null || input.Addresses.Length > 32 ||
            input.Addresses.Any(x => !Required(x, 80) || !IPAddress.TryParse(x, out _)) ||
            input.Capabilities is null || input.Capabilities.Length > 20 ||
            input.Capabilities.Any(x => !Required(x, 40)) ||
            input.LastScanStatus is not ("scanned" or "partial_scan" or "not_scanned"))
            return Results.BadRequest();

        device.Hostname = input.Hostname;
        device.Os = input.Os;
        device.AgentVersion = input.AgentVersion;
        device.AddressesJson = Storage.Write(input.Addresses.Distinct());
        device.CapabilitiesJson = Storage.Write(input.Capabilities.Distinct());
        device.ReportedScanStatus = input.LastScanStatus;
        device.LastHeartbeat = Storage.Now;
        device.Revision++;
        return await Save(db, ct);
    }

    private static async Task<IResult> Inventory(Inventory input, HttpContext context, GuardDb db,
        SignatureCatalog catalog, CancellationToken ct)
    {
        var device = await Authenticate(context, db, ct);
        if (device is null)
            return Results.Unauthorized();
        if (!ValidInventory(input))
            return Results.BadRequest();
        try
        {
            await InventoryIngestion.Apply(db, catalog, device, input, ct);
            return Results.NoContent();
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
            if (await db.Receipts.FindAsync([device.Id, input.ScanId], ct) is not null)
                return Results.NoContent();
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static async Task<IResult> Rotate(Rotation input, HttpContext context, GuardDb db, CancellationToken ct)
    {
        var device = await Authenticate(context, db, ct);
        if (device is null)
            return Results.Unauthorized();
        if (input.ProtocolVersion != Protocol.Version || !Secrets.Valid(input.Credential))
            return Results.BadRequest();
        if (Secrets.Matches(input.Credential, device.CredentialHash))
            return Results.NoContent();
        device.CredentialHash = Secrets.Hash(input.Credential);
        device.Revision++;
        return await Save(db, ct);
    }

    private static async Task<IResult> Save(GuardDb db, CancellationToken ct)
    {
        try
        {
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }
        catch (DbUpdateConcurrencyException)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static async Task<Device?> Authenticate(HttpContext context, GuardDb db, CancellationToken ct)
    {
        var authorization = context.Request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;
        var pair = authorization[7..].Split('.', 2);
        if (pair.Length != 2 || !Guid.TryParseExact(pair[0], "D", out var id) || !Secrets.Valid(pair[1]))
            return null;
        var device = await db.Devices.FindAsync([id], ct);
        return device is not null && Secrets.Matches(pair[1], device.CredentialHash) ? device : null;
    }

    private static bool ValidInventory(Inventory report) =>
        report.ProtocolVersion == Protocol.Version && report.ScanId != Guid.Empty &&
        report.ScannedAt >= DateTimeOffset.UnixEpoch && report.ScannedAt <= DateTimeOffset.UtcNow.AddMinutes(5) &&
        report.Coverage is { Length: > 0 and <= 20 } &&
        report.Coverage.All(x => x is not null && Required(x.Source, 40) && x.Entries >= 0 &&
            x.Status is "complete" or "partial" or "unavailable" && Optional(x.Reason, 200)) &&
        report.Coverage.Select(x => x.Source).Distinct(StringComparer.Ordinal).Count() == report.Coverage.Length &&
        report.Observations is { Length: <= Protocol.MaxObservations } &&
        report.Observations.All(x => x is not null && x.Kind is "registry" or "process" or "service" or "autorun" or "task" &&
            Required(x.Name, 512) && Optional(x.Path, 1024) && Optional(x.Publisher, 256) &&
            Optional(x.Product, 256) && Optional(x.OriginalFilename, 256) && Optional(x.Version, 128));

    private static bool Required(string? value, int max) => !string.IsNullOrWhiteSpace(value) && Optional(value, max);
    private static bool Optional(string? value, int max) =>
        value is null || (value.Length <= max && !value.Any(char.IsControl));
}

public static class Secrets
{
    public static string Create() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public static bool Valid(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Convert.FromHexString(value)));
    public static bool Matches(string value, string hash) => hash.Length == 64 &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(Hash(value)), Convert.FromHexString(hash));
}
