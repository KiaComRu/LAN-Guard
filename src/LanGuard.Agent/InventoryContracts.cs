using LanGuard.Shared;

namespace LanGuard.Agent;

public interface IEndpointInventoryProvider
{
    Inventory Collect(CancellationToken cancellationToken);
}

public interface IProcessEventSource
{
    IAsyncEnumerable<Observation> ReadAsync(CancellationToken cancellationToken);
}

public interface IPolicyProvider
{
    Task<PolicyAssessment> AssessAsync(CancellationToken cancellationToken);
}

public sealed record PolicyAssessment(bool AuditAvailable, string[] Limitations);
