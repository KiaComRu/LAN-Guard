using System.Text.RegularExpressions;

namespace LanGuard.Shared;

public static partial class Detector
{
    public static Match[] MatchInventory(SignatureCatalog catalog, IEnumerable<Observation> inventory)
    {
        var observations = inventory.ToArray();
        var matches = new List<Match>();
        foreach (var rule in catalog.Rules)
        {
            var evidence = observations.Select(observation => FindEvidence(rule, observation))
                .OfType<Evidence>().ToArray();
            if (evidence.Length == 0)
                continue;

            // Name and OriginalFilename are correlated. An unverified publisher alone never anchors a match.
            var corroborated = evidence.Any(item => item.MatchedFields.Contains("publisher") ||
                (item.MatchedFields.Contains("product") && item.MatchedFields.Contains("originalFilename"))) ||
                evidence.Select(item => item.Observation.Kind).Distinct().Count() > 1;
            matches.Add(new Match(rule.Id, rule.ProductFamily, rule.Category, rule.SeveritySuggestion,
                corroborated ? "medium" : "low",
                evidence.OrderByDescending(item => item.MatchedFields.Length)
                    .Select(item => item.Observation.Version).FirstOrDefault(version => !string.IsNullOrWhiteSpace(version)),
                evidence.Any(item => item.Observation.Kind == "process"), evidence));
        }

        return [.. matches];
    }

    private static Evidence? FindEvidence(SignatureRule rule, Observation observation)
    {
        var fields = new List<string>();
        var names = observation.Kind switch
        {
            "service" => rule.ServiceNames,
            "process" or "task" or "autorun" => rule.ProcessNames,
            _ => rule.Aliases
        };
        if (Matches(names, observation.Name) || Matches(rule.Aliases, observation.Name))
            fields.Add("name");
        if (Matches(rule.ExecutableOriginalNames, observation.OriginalFilename))
            fields.Add("originalFilename");
        if (Matches(rule.ProductMetadata, observation.Product))
            fields.Add("product");
        if (fields.Count == 0)
            return null;
        if (Matches(rule.Publishers, observation.Publisher))
            fields.Add("publisher");
        return new Evidence(observation, [.. fields]);
    }

    private static bool Matches(IEnumerable<string> expected, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        return expected.Any(candidate => string.Equals(Normalize(candidate), Normalize(value),
            StringComparison.OrdinalIgnoreCase));
    }

    private static string Normalize(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed[..^4];
        return Separators().Replace(trimmed, " ");
    }

    [GeneratedRegex(@"[\s_-]+")]
    private static partial Regex Separators();
}
