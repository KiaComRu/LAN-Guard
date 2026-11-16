using LanGuard.Shared;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace LanGuard.Server;

public record ServerMode(bool Demo);

public static class Bootstrap
{
    public static async Task Initialize(IServiceProvider services, IConfiguration configuration, bool demo)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<GuardDb>();
        await db.Database.MigrateAsync();
        if (!await db.Admins.AnyAsync())
        {
            var login = configuration["LanGuard:AdminLogin"]?.Trim() ?? "admin";
            var password = configuration["LanGuard:AdminPassword"];
            if (login.Length is < 1 or > 100 || password is null || password.Length is < 16 or > 256)
                throw new InvalidOperationException("Set LanGuard__AdminPassword (16–256 characters) before first start.");
            var admin = new Admin { Login = login.ToLowerInvariant() };
            admin.PasswordHash = scope.ServiceProvider.GetRequiredService<IPasswordHasher<Admin>>()
                .HashPassword(admin, password);
            db.Admins.Add(admin);
            await db.SaveChangesAsync();
        }

        if (!demo)
            return;

        var catalog = scope.ServiceProvider.GetRequiredService<SignatureCatalog>();
        var fixtures = Storage.Read<DemoDevice[]>(await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "fixtures", "demo.json")));
        foreach (var fixture in fixtures)
        {
            var device = await db.Devices.FindAsync(fixture.Id);
            if (device?.LastScanAt is not null || device is { HasAgent: false })
                continue;
            if (device is null)
            {
                device = new Device
                {
                    Id = fixture.Id, Hostname = fixture.Hostname, Os = fixture.Os,
                    AddressesJson = Storage.Write(fixture.Addresses), HasAgent = fixture.Inventory is not null,
                    AgentVersion = fixture.Inventory is null ? "" : "1.0.0",
                    LastHeartbeat = fixture.Inventory is null ? null : Storage.Now
                };
                db.Devices.Add(device);
                await db.SaveChangesAsync();
            }
            if (fixture.Inventory is not null)
                await InventoryIngestion.Apply(db, catalog, device, fixture.Inventory with
                {
                    ScannedAt = DateTimeOffset.UtcNow
                }, CancellationToken.None);
        }
    }

    private sealed record DemoDevice(Guid Id, string Hostname, string Os, string[] Addresses, Inventory? Inventory);
}
