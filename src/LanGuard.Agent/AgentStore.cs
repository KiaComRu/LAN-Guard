using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using LanGuard.Shared;

namespace LanGuard.Agent;

[SupportedOSPlatform("windows")]
public sealed class AgentStore(string root)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private string IdentityPath => Path.Combine(root, "identity.bin");
    private string BootstrapPath => Path.Combine(root, "enrollment.token");
    private string QueuePath => Path.Combine(root, "inventory");
    private const int QueueLimit = 64;
    public const long QueueByteLimit = 64 * 1024 * 1024;

    public AgentIdentity LoadOrCreate()
    {
        if (File.Exists(IdentityPath))
            return JsonSerializer.Deserialize<AgentIdentity>(
                ProtectedData.Unprotect(File.ReadAllBytes(IdentityPath), null, DataProtectionScope.CurrentUser), Json)
                ?? throw new InvalidDataException("Agent identity is invalid.");
        if (!File.Exists(BootstrapPath))
            throw new InvalidOperationException("Enrollment token is missing.");
        var identity = new AgentIdentity(Guid.NewGuid(), CreateSecret(), false, DateTimeOffset.UtcNow, null);
        Save(identity);
        return identity;
    }

    public string ReadToken() => File.ReadAllText(BootstrapPath).Trim();
    public void RemoveToken() => File.Delete(BootstrapPath);
    public void Save(AgentIdentity identity) => WriteAtomically(IdentityPath,
        ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(identity, Json), null, DataProtectionScope.CurrentUser));
    public static string CreateSecret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public FileInfo[] Pending()
    {
        Directory.CreateDirectory(QueuePath);
        return new DirectoryInfo(QueuePath).GetFiles("*.json").OrderBy(file => file.Name, StringComparer.Ordinal).ToArray();
    }

    public bool Queue(Inventory inventory)
    {
        var pending = Pending();
        var rejected = new DirectoryInfo(QueuePath).GetFiles("*.rejected").OrderBy(file => file.Name, StringComparer.Ordinal);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(inventory, Json);
        var totalSize = pending.Sum(file => file.Length) + rejected.Sum(file => file.Length);
        foreach (var file in rejected)
        {
            if (totalSize + bytes.Length <= QueueByteLimit)
                break;
            totalSize -= file.Length;
            file.Delete();
        }
        if (pending.Length >= QueueLimit || totalSize + bytes.Length > QueueByteLimit)
            return false;
        var stamp = inventory.ScannedAt.ToUnixTimeMilliseconds();
        WriteAtomically(Path.Combine(QueuePath, $"{stamp:D16}-{inventory.ScanId:N}.json"), bytes);
        return true;
    }

    private static void WriteAtomically(string path, byte[] bytes)
    {
        var temporary = path + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: true);
    }
}

public sealed record AgentIdentity(Guid Id, string Credential, bool Enrolled, DateTimeOffset RotatedAt, string? PendingCredential);
