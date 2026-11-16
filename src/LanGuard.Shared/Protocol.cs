namespace LanGuard.Shared;

public static class Protocol
{
    public const int Version = 1;
    public const int MaxObservations = 5000;
    public static readonly string[] RequiredSources = ["machineRegistry", "userRegistry", "services", "processes"];
}

public record Enrollment(int ProtocolVersion, Guid AgentId, string Token, string Credential);
public record Rotation(int ProtocolVersion, string Credential);
public record Heartbeat(int ProtocolVersion, string Hostname, string Os, string AgentVersion,
    string[] Addresses, string[] Capabilities, string LastScanStatus);
public record Coverage(string Source, string Status, int Entries, string? Reason = null);
public record Observation(string Kind, string Name, string? Path = null, string? Publisher = null,
    string? Product = null, string? OriginalFilename = null, string? Version = null);
public record Inventory(int ProtocolVersion, Guid ScanId, DateTimeOffset ScannedAt,
    Coverage[] Coverage, Observation[] Observations);

public record SignatureCatalog(int Version, SignatureRule[] Rules);
public record SignatureRule(string Id, string ProductFamily, string Category, string SeveritySuggestion,
    int Version, string[] Aliases, string[] ServiceNames, string[] ProcessNames, string[] ExecutableOriginalNames,
    string[] Publishers, string[] ProductMetadata, string[]? FileHashes = null,
    string[]? Signatures = null, string? Notes = null);
public record Evidence(Observation Observation, string[] MatchedFields);
public record Match(string FamilyId, string ProductFamily, string Category, string RiskLevel,
    string Confidence, string? Version, bool CurrentlyRunning, Evidence[] Evidence);
