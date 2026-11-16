using System.Text.Json;
using LanGuard.Shared;
using Microsoft.EntityFrameworkCore;

namespace LanGuard.Server;

public class GuardDb(DbContextOptions options) : DbContext(options)
{
    public DbSet<Admin> Admins => Set<Admin>();
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<Detection> Detections => Set<Detection>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<Receipt> Receipts => Set<Receipt>();
    public DbSet<HistoryEvent> Events => Set<HistoryEvent>();
    public DbSet<AuditEntry> Audit => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<Admin>().ToTable("admins").HasIndex(x => x.Login).IsUnique();
        model.Entity<Device>().ToTable("devices").Property(x => x.Revision).IsConcurrencyToken();
        model.Entity<Detection>().ToTable("detections").HasKey(x => new { x.DeviceId, x.FamilyId });
        model.Entity<Detection>().HasOne<Device>().WithMany().HasForeignKey(x => x.DeviceId);
        model.Entity<EnrollmentToken>().ToTable("enrollment_tokens").Property(x => x.UsedAt).IsConcurrencyToken();
        model.Entity<Receipt>().ToTable("inventory_receipts").HasKey(x => new { x.DeviceId, x.ScanId });
        model.Entity<Receipt>().HasOne<Device>().WithMany().HasForeignKey(x => x.DeviceId);
        model.Entity<HistoryEvent>().ToTable("events").HasIndex(x => new { x.DeviceId, x.OccurredAt });
        model.Entity<HistoryEvent>().HasOne<Device>().WithMany().HasForeignKey(x => x.DeviceId);
        model.Entity<AuditEntry>().ToTable("audit_log").HasIndex(x => x.OccurredAt);
    }
}

public sealed class PostgresGuardDb(DbContextOptions<PostgresGuardDb> options) : GuardDb(options);

public sealed class Admin
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required string Login { get; init; }
    public string PasswordHash { get; set; } = "";
    public string Role { get; init; } = "administrator";
    public long CreatedAt { get; init; } = Storage.Now;
    public long? LastLogin { get; set; }
}

public sealed class Device
{
    public Guid Id { get; init; }
    public string Hostname { get; set; } = "";
    public string Os { get; set; } = "";
    public string AgentVersion { get; set; } = "";
    public string CredentialHash { get; set; } = "";
    public string AddressesJson { get; set; } = "[]";
    public string CapabilitiesJson { get; set; } = "[]";
    public string CoverageJson { get; set; } = "[]";
    public string AuditStatus { get; set; } = "not_scanned";
    public string ReportedScanStatus { get; set; } = "not_scanned";
    public bool HasAgent { get; init; } = true;
    public long FirstSeen { get; init; } = Storage.Now;
    public long? LastHeartbeat { get; set; }
    public long? LastScanAt { get; set; }
    public long Revision { get; set; }
}

public sealed class Detection
{
    public Guid DeviceId { get; init; }
    public required string FamilyId { get; init; }
    public required string MatchJson { get; set; }
    public bool Present { get; set; } = true;
    public long FirstSeen { get; init; }
    public long LastSeen { get; set; }
}

public sealed class EnrollmentToken
{
    public required string Id { get; init; }
    public long ExpiresAt { get; init; }
    public long? UsedAt { get; set; }
}

public sealed class Receipt
{
    public Guid DeviceId { get; init; }
    public Guid ScanId { get; init; }
    public long ReceivedAt { get; init; } = Storage.Now;
}

public sealed class HistoryEvent
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid DeviceId { get; init; }
    public string? FamilyId { get; init; }
    public required string Type { get; init; }
    public long OccurredAt { get; init; }
}

public sealed class AuditEntry
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required string Actor { get; init; }
    public required string Action { get; init; }
    public long OccurredAt { get; init; } = Storage.Now;
}

public static class Storage
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static long Now => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public static DateTimeOffset Date(long value) => DateTimeOffset.FromUnixTimeMilliseconds(value);
    public static DateTimeOffset? Date(long? value) => value is long time ? Date(time) : null;
    public static T Read<T>(string json) => JsonSerializer.Deserialize<T>(json, Json)!;
    public static string Write<T>(T data) => JsonSerializer.Serialize(data, Json);
}
