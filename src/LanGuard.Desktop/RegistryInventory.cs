using System.Security;
using LanGuard.Shared;
using Microsoft.Win32;

namespace LanGuard.Desktop;

internal sealed record RegistryReport(string? Hostname, string Status, string Message, Match[] Matches);

internal static class RegistryInventory
{
    private const string Uninstall = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    private const int MaxEntries = 4096;

    public static RegistryReport Read(string? target)
    {
        var observations = new HashSet<Observation>();
        var issues = new HashSet<string>();
        var catalog = Program.ReadCatalog();
        var machineViews = 0;
        var inspected = 0;
        string? hostname = target is null ? Environment.MachineName : null;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var machine = Open(RegistryHive.LocalMachine, view, target);
                ReadEntries(machine, Uninstall);
                machineViews++;
                if (hostname is null)
                {
                    using var identity = machine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName");
                    hostname = Clean(identity?.GetValue("ComputerName") as string);
                }
            }
            catch (Exception exception) when (IsRegistryError(exception))
            {
                issues.Add(Describe(exception));
            }
        }
        if (machineViews == 0)
            return new RegistryReport(hostname, "unavailable", string.Join(". ", issues), []);

        var profiles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var users = Open(RegistryHive.Users, view, target);
                foreach (var profile in users.GetSubKeyNames().Where(IsProfile))
                {
                    profiles.Add(profile);
                    ReadEntries(users, profile + @"\" + Uninstall);
                }
            }
            catch (Exception exception) when (IsRegistryError(exception))
            {
                issues.Add(Describe(exception));
            }
        }
        if (profiles.Count == 0)
            issues.Add("Нет доступных загруженных профилей");
        var matches = Detector.MatchInventory(catalog, observations)
            .Where(item => item.Category == "third_party").OrderBy(item => item.ProductFamily).ToArray();
        var coverage = $"Системный реестр: {machineViews}/2. Загруженных профилей: {profiles.Count}.";
        return new RegistryReport(hostname, issues.Count == 0 ? "checked" : "partial",
            issues.Count == 0 ? coverage : coverage + " " + string.Join(". ", issues) + ".", matches);

        void ReadEntries(RegistryKey root, string path)
        {
            using var key = root.OpenSubKey(path);
            if (key is null)
                return;
            foreach (var subkey in key.GetSubKeyNames())
            {
                if (++inspected > MaxEntries)
                {
                    issues.Add("Достигнут предел числа записей");
                    break;
                }
                try
                {
                    using var entry = key.OpenSubKey(subkey);
                    if (Clean(entry?.GetValue("DisplayName") as string) is not { } name)
                        continue;
                    observations.Add(new Observation("registry", name,
                        Publisher: Clean(entry!.GetValue("Publisher") as string),
                        Version: Clean(entry.GetValue("DisplayVersion") as string)));
                }
                catch (Exception exception) when (IsRegistryError(exception))
                {
                    issues.Add(Describe(exception));
                }
            }
        }
    }

    private static RegistryKey Open(RegistryHive hive, RegistryView view, string? target) => target is null
        ? RegistryKey.OpenBaseKey(hive, view)
        : RegistryKey.OpenRemoteBaseKey(hive, target, view);

    private static bool IsProfile(string name) =>
        (name.StartsWith("S-1-5-21-", StringComparison.Ordinal) || name.StartsWith("S-1-12-1-", StringComparison.Ordinal)) &&
        name[2..].All(character => char.IsAsciiDigit(character) || character == '-');

    private static string? Clean(string? text) => string.IsNullOrWhiteSpace(text)
        ? null : string.Concat(text.Where(character => !char.IsControl(character)).Take(512)).Trim();

    private static bool IsRegistryError(Exception error) => error is IOException or UnauthorizedAccessException or SecurityException;
    private static string Describe(Exception error) => error is UnauthorizedAccessException or SecurityException
        ? "Отказано в доступе к реестру" : "Удалённый реестр недоступен или соединение прервано";
}
