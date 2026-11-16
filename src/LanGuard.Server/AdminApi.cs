using System.Security.Claims;
using System.Text;
using LanGuard.Shared;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace LanGuard.Server;

public static class AdminApi
{
    public static void MapAdminApi(this WebApplication app)
    {
        var api = app.MapGroup("/api/v1");
        api.MapGet("/auth/csrf", (HttpContext http, IAntiforgery csrf) =>
            Results.Ok(new { token = csrf.GetAndStoreTokens(http).RequestToken }));
        api.MapPost("/auth/login", Login).RequireRateLimiting("auth");
        api.MapPost("/auth/logout", Logout).RequireAuthorization();
        var admin = api.MapGroup("").RequireAuthorization();
        admin.MapGet("/auth/session", (ClaimsPrincipal user, ServerMode mode) =>
            Results.Ok(new { login = user.Identity!.Name, role = user.FindFirstValue(ClaimTypes.Role), mode.Demo }));
        admin.MapGet("/overview", Overview);
        admin.MapGet("/devices", Devices);
        admin.MapGet("/devices/{id:guid}", Detail);
        admin.MapGet("/detections", Detections);
        admin.MapGet("/events", Events);
        admin.MapGet("/reports/detections.csv", Export);
        admin.MapGet("/signatures", (SignatureCatalog catalog) => catalog).RequireAuthorization("administrator");
        admin.MapPost("/enrollment-tokens", IssueToken).RequireAuthorization("administrator");
    }

    private static async Task<IResult> Login(LoginRequest input, HttpContext http, IAntiforgery csrf,
        GuardDb db, IPasswordHasher<Admin> hasher, CancellationToken ct)
    {
        if (!await csrf.IsRequestValidAsync(http))
            return Results.BadRequest();
        if (input.Login is not { Length: > 0 and <= 100 } || input.Password is not { Length: > 0 and <= 256 })
            return Results.Unauthorized();
        var login = input.Login.Trim().ToLowerInvariant();
        var admin = await db.Admins.SingleOrDefaultAsync(x => x.Login == login, ct);
        // An existing hash also covers failed lookups, keeping the password work comparable.
        var candidate = admin ?? await db.Admins.AsNoTracking().FirstAsync(ct);
        var verification = hasher.VerifyHashedPassword(candidate, candidate.PasswordHash, input.Password);
        if (admin is null || verification == PasswordVerificationResult.Failed)
        {
            db.Audit.Add(new AuditEntry { Actor = "anonymous", Action = "login_failed" });
            await db.SaveChangesAsync(ct);
            return Results.Unauthorized();
        }

        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
            admin.PasswordHash = hasher.HashPassword(admin, input.Password);
        admin.LastLogin = Storage.Now;
        db.Audit.Add(new AuditEntry { Actor = admin.Login, Action = "login" });
        await db.SaveChangesAsync(ct);
        var identity = new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, admin.Id.ToString()),
            new Claim(ClaimTypes.Name, admin.Login),
            new Claim(ClaimTypes.Role, admin.Role)
        ], CookieAuthenticationDefaults.AuthenticationScheme);
        await http.SignInAsync(new ClaimsPrincipal(identity));
        return Results.NoContent();
    }

    private static async Task<IResult> Logout(HttpContext http, IAntiforgery csrf, GuardDb db, CancellationToken ct)
    {
        if (!await csrf.IsRequestValidAsync(http))
            return Results.BadRequest();
        db.Audit.Add(new AuditEntry { Actor = http.User.Identity!.Name!, Action = "logout" });
        await db.SaveChangesAsync(ct);
        await http.SignOutAsync();
        return Results.NoContent();
    }

    private static async Task<IResult> IssueToken(HttpContext http, IAntiforgery csrf, GuardDb db,
        ServerMode mode, CancellationToken ct)
    {
        if (mode.Demo)
            return Results.NotFound();
        if (!await csrf.IsRequestValidAsync(http))
            return Results.BadRequest();
        var token = Secrets.Create();
        var expires = Storage.Now + (long)TimeSpan.FromMinutes(30).TotalMilliseconds;
        db.EnrollmentTokens.Add(new EnrollmentToken { Id = Secrets.Hash(token), ExpiresAt = expires });
        db.Audit.Add(new AuditEntry { Actor = http.User.Identity!.Name!, Action = "enrollment_token_created" });
        await db.SaveChangesAsync(ct);
        return Results.Ok(new { token, expiresAt = Storage.Date(expires) });
    }

    private static async Task<IResult> Overview(GuardDb db, ServerMode mode, CancellationToken ct)
    {
        var devices = await db.Devices.AsNoTracking().ToListAsync(ct);
        var detections = await db.Detections.AsNoTracking().Where(x => x.Present).ToListAsync(ct);
        var live = devices.Where(device => Online(device, mode)).ToDictionary(x => x.Id);
        return Results.Ok(new
        {
            mode.Demo, devices = devices.Count, online = live.Count,
            unverified = devices.Count(x => x.AuditStatus != "scanned" || !live.ContainsKey(x.Id)),
            detections = detections.Count,
            active = detections.Count(x => live.TryGetValue(x.DeviceId, out var device) &&
                Running(Storage.Read<Match>(x.MatchJson), x, device, online: true) == true),
            eventsToday = await db.Events.CountAsync(x => x.OccurredAt >= Storage.Now - 86400000, ct)
        });
    }

    private static async Task<IResult> Devices(GuardDb db, ServerMode mode, string? q, string? status, int? page, CancellationToken ct)
    {
        if (q?.Length > 100 || page is < 1 or > 100_000)
            return Results.BadRequest();
        var devices = db.Devices.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var term = q.Trim().ToLowerInvariant();
            devices = devices.Where(x => x.Hostname.ToLower().Contains(term) || x.AddressesJson.Contains(term));
        }
        if (!string.IsNullOrEmpty(status))
            devices = devices.Where(x => x.AuditStatus == status);
        var total = await devices.CountAsync(ct);
        var rows = await devices.OrderBy(x => x.Hostname).ThenBy(x => x.Id)
            .Skip(((page ?? 1) - 1) * 50).Take(50).ToArrayAsync(ct);
        var ids = rows.Select(x => x.Id).ToArray();
        var matches = (await db.Detections.AsNoTracking().Where(x => x.Present && ids.Contains(x.DeviceId))
            .ToListAsync(ct)).ToLookup(x => x.DeviceId);
        return Results.Ok(new { total, items = rows.Select(x => DeviceView(x, matches[x.Id], mode)) });
    }

    private static async Task<IResult> Detail(Guid id, GuardDb db, ServerMode mode, CancellationToken ct)
    {
        var device = await db.Devices.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (device is null)
            return Results.NotFound();
        var matches = await db.Detections.AsNoTracking().Where(x => x.DeviceId == id && x.Present)
            .OrderBy(x => x.FamilyId).ToListAsync(ct);
        var history = await db.Events.AsNoTracking().Where(x => x.DeviceId == id)
            .OrderByDescending(x => x.OccurredAt).ThenBy(x => x.Id).Take(50).ToListAsync(ct);
        return Results.Ok(new
        {
            device = DeviceView(device, matches, mode), device.AgentVersion,
            capabilities = Storage.Read<string[]>(device.CapabilitiesJson),
            coverage = Storage.Read<Coverage[]>(device.CoverageJson), events = history.Select(EventView)
        });
    }

    private static async Task<IResult> Detections(GuardDb db, ServerMode mode, string? family, int? page, CancellationToken ct)
    {
        if (family?.Length > 80 || page is < 1 or > 100_000)
            return Results.BadRequest();
        var rows = CurrentDetections(db, family);
        var total = await rows.CountAsync(ct);
        var results = await rows.OrderByDescending(x => x.Detection.LastSeen).ThenBy(x => x.Detection.DeviceId)
            .ThenBy(x => x.Detection.FamilyId).Skip(((page ?? 1) - 1) * 50).Take(50).ToListAsync(ct);
        return Results.Ok(new
        {
            total, items = results.Select(x => new { x.Device.Id, x.Device.Hostname,
                detection = DetectionView(x.Detection, x.Device, Online(x.Device, mode)) })
        });
    }

    private static IQueryable<DetectionRow> CurrentDetections(GuardDb db, string? family) =>
        from detection in db.Detections.AsNoTracking()
        join device in db.Devices.AsNoTracking() on detection.DeviceId equals device.Id
        where detection.Present && (family == null || detection.FamilyId == family)
        select new DetectionRow { Device = device, Detection = detection };

    private static async Task<IResult> Events(GuardDb db, CancellationToken ct)
    {
        var history = await db.Events.AsNoTracking().OrderByDescending(x => x.OccurredAt)
            .ThenBy(x => x.Id).Take(100).ToListAsync(ct);
        return Results.Ok(history.Select(EventView));
    }

    private static async Task<IResult> Export(GuardDb db, ServerMode mode, CancellationToken ct)
    {
        var rows = await CurrentDetections(db, null).OrderBy(x => x.Detection.DeviceId)
            .ThenBy(x => x.Detection.FamilyId).ToListAsync(ct);
        var csv = new StringBuilder("Компьютер,Программа,Уверенность,Последнее обнаружение,Демонстрация\r\n");
        foreach (var row in rows)
        {
            var match = Storage.Read<Match>(row.Detection.MatchJson);
            csv.AppendJoin(',', Csv(row.Device.Hostname), Csv(match.ProductFamily), Csv(match.Confidence),
                Storage.Date(row.Detection.LastSeen).ToString("O"), mode.Demo ? "да" : "нет").Append("\r\n");
        }
        return Results.File(Encoding.UTF8.GetBytes("\uFEFF" + csv), "text/csv; charset=utf-8", "lan-guard-detections.csv");
    }

    private static string Csv(string value)
    {
        if (value.TrimStart().StartsWithAny('=', '+', '-', '@'))
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    private static bool StartsWithAny(this string value, params char[] prefixes) =>
        value.Length > 0 && prefixes.Contains(value[0]);

    private static bool Online(Device device, ServerMode mode) =>
        device.HasAgent && (mode.Demo || device.LastHeartbeat > Storage.Now - 180_000);

    private static object DeviceView(Device device, IEnumerable<Detection> detections, ServerMode mode)
    {
        var online = Online(device, mode);
        var matches = detections.Select(x => DetectionView(x, device, online)).ToArray();
        return new
        {
            device.Id, device.Hostname, device.Os, device.HasAgent, online, device.AuditStatus,
            result = matches.Length > 0 ? "detected" :
                device.AuditStatus == "scanned" && online ? "not_detected" :
                device.AuditStatus == "not_scanned" ? "not_scanned" : "unknown",
            addresses = Storage.Read<string[]>(device.AddressesJson),
            firstSeen = Storage.Date(device.FirstSeen),
            lastHeartbeat = Storage.Date(device.LastHeartbeat),
            lastScanAt = Storage.Date(device.LastScanAt),
            detections = matches
        };
    }

    private static object DetectionView(Detection detection, Device device, bool online)
    {
        var match = Storage.Read<Match>(detection.MatchJson);
        return new
        {
            match.FamilyId, match.ProductFamily, match.Category, match.RiskLevel, match.Confidence,
            match.Version, match.Evidence,
            currentlyRunning = Running(match, detection, device, online),
            firstSeen = Storage.Date(detection.FirstSeen), lastSeen = Storage.Date(detection.LastSeen)
        };
    }

    private static bool? Running(Match match, Detection detection, Device device, bool online)
    {
        if (!online || device.LastScanAt != detection.LastSeen)
            return null;
        if (match.Evidence.Any(item => item.Observation.Kind == "process"))
            return true;
        return Storage.Read<Coverage[]>(device.CoverageJson).Any(item =>
            item is { Source: "processes", Status: "complete" }) ? false : null;
    }

    private static object EventView(HistoryEvent entry) =>
        new { entry.Id, entry.DeviceId, entry.FamilyId, entry.Type, occurredAt = Storage.Date(entry.OccurredAt) };

    private sealed class DetectionRow
    {
        public required Device Device { get; init; }
        public required Detection Detection { get; init; }
    }
    public sealed record LoginRequest(string Login, string Password);
}
