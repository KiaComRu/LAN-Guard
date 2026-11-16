using System.Threading.RateLimiting;
using LanGuard.Server;
using LanGuard.Shared;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Serilog;

var builder = WebApplication.CreateBuilder(args);
var demo = builder.Configuration.GetValue<bool>("LanGuard:Demo");
var dataPath = Path.GetFullPath(builder.Configuration["LanGuard:DataPath"] ?? "data");
Directory.CreateDirectory(dataPath);
var connection = builder.Configuration.GetConnectionString("Postgres");
if (demo && !string.IsNullOrEmpty(connection))
    throw new InvalidOperationException("Demo uses a separate SQLite database.");
if (string.IsNullOrEmpty(connection))
    builder.Services.AddDbContext<GuardDb>(options =>
        options.UseSqlite(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(dataPath, demo ? "demo.db" : "languard.db")
        }.ToString()));
else
    builder.Services.AddDbContext<GuardDb, PostgresGuardDb>(options => options.UseNpgsql(connection));
builder.Services.AddSingleton(new ServerMode(demo));
builder.Services.AddSingleton(Storage.Read<SignatureCatalog>(File.ReadAllText(
    builder.Configuration["LanGuard:SignaturesPath"] ??
    Path.Combine(AppContext.BaseDirectory, "signatures", "remote-access.json"))));
builder.Services.AddSingleton<Microsoft.AspNetCore.Identity.IPasswordHasher<Admin>,
    Microsoft.AspNetCore.Identity.PasswordHasher<Admin>>();
builder.Services.AddDataProtection().SetApplicationName(demo ? "LanGuard.Demo" : "LanGuard")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataPath, "keys")));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
{
    options.Cookie.Name = "__Host-LanGuard";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; };
    options.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
});
builder.Services.AddAuthorizationBuilder().AddPolicy("administrator", policy => policy.RequireRole("administrator"));
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-Token";
    options.Cookie.Name = "__Host-LanGuard-Csrf";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 12, Window = TimeSpan.FromMinutes(1) }));
});
builder.Services.AddOpenApi();
builder.Services.AddHealthChecks();
builder.Host.UseSerilog((_, logger) => logger.WriteTo.Console());
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 8 * 1024 * 1024);

var app = builder.Build();
await Bootstrap.Initialize(app.Services, app.Configuration, demo);
app.UseExceptionHandler(handler => handler.Run(context =>
    Results.Problem(statusCode: 500, title: "Ошибка сервера").ExecuteAsync(context)));
app.Use(async (context, next) =>
{
    if (!context.Request.IsHttps)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsync("HTTPS required.");
        return;
    }
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    if (context.Request.Path.StartsWithSegments("/api"))
        context.Response.Headers.CacheControl = "no-store";
    await next(context);
});
app.UseSerilogRequestLogging();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.MapHealthChecks("/healthz");
app.MapOpenApi().RequireAuthorization("administrator");
app.MapAdminApi();
app.MapAgentApi();
await app.RunAsync();

public partial class Program;
