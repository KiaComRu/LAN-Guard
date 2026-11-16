using LanGuard.Shared;
using Microsoft.EntityFrameworkCore;

namespace LanGuard.Server;

public static class InventoryIngestion
{
    public static async Task Apply(GuardDb db, SignatureCatalog catalog, Device device, Inventory report,
        CancellationToken cancellationToken)
    {
        if (await db.Receipts.FindAsync([device.Id, report.ScanId], cancellationToken) is not null)
            return;

        var observedAt = report.ScannedAt.ToUnixTimeMilliseconds();
        db.Receipts.Add(new Receipt { DeviceId = device.Id, ScanId = report.ScanId });
        if (device.LastScanAt >= observedAt)
        {
            await db.SaveChangesAsync(cancellationToken);
            return;
        }

        var existing = await db.Detections.Where(x => x.DeviceId == device.Id)
            .ToDictionaryAsync(x => x.FamilyId, cancellationToken);
        var matches = Detector.MatchInventory(catalog, report.Observations);
        var sourceStatus = report.Coverage.ToDictionary(x => x.Source, x => x.Status);
        var complete = Protocol.RequiredSources.All(sourceStatus.ContainsKey) &&
            sourceStatus.Values.All(status => status == "complete");
        var processesComplete = sourceStatus.GetValueOrDefault("processes") == "complete";

        foreach (var match in matches)
        {
            if (!existing.Remove(match.FamilyId, out var detection))
            {
                detection = new Detection
                {
                    DeviceId = device.Id, FamilyId = match.FamilyId, FirstSeen = observedAt,
                    LastSeen = observedAt, MatchJson = Storage.Write(match)
                };
                db.Detections.Add(detection);
                AddEvent(db, device, match.FamilyId, "detected", observedAt);
                if (match.CurrentlyRunning)
                    AddEvent(db, device, match.FamilyId, "started", observedAt);
                continue;
            }

            var previous = Storage.Read<Match>(detection.MatchJson);
            if (!detection.Present)
                AddEvent(db, device, match.FamilyId, "reappeared", observedAt);
            if (match.CurrentlyRunning && (!detection.Present || !previous.CurrentlyRunning))
                AddEvent(db, device, match.FamilyId, "started", observedAt);
            var effectiveMatch = match with
            {
                CurrentlyRunning = match.CurrentlyRunning || (!processesComplete &&
                    detection.Present && previous.CurrentlyRunning)
            };
            detection.Present = true;
            detection.LastSeen = observedAt;
            detection.MatchJson = Storage.Write(effectiveMatch);
        }

        if (complete)
        {
            foreach (var missing in existing.Values.Where(x => x.Present))
            {
                missing.Present = false;
                AddEvent(db, device, missing.FamilyId, "no_longer_observed", observedAt);
            }
        }
        else if (device.AuditStatus != "partial_scan")
        {
            AddEvent(db, device, null, "partial_scan", observedAt);
        }

        device.LastScanAt = observedAt;
        device.CoverageJson = Storage.Write(report.Coverage);
        device.AuditStatus = complete ? "scanned" : "partial_scan";
        device.Revision++;
        await db.SaveChangesAsync(cancellationToken);
    }

    private static void AddEvent(GuardDb db, Device device, string? family, string type, long time) =>
        db.Events.Add(new HistoryEvent { DeviceId = device.Id, FamilyId = family, Type = type, OccurredAt = time });
}
