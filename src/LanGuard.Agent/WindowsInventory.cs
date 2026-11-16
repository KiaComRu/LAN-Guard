using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using LanGuard.Shared;
using Microsoft.Win32;

namespace LanGuard.Agent;

[SupportedOSPlatform("windows")]
public sealed partial class WindowsInventory : IEndpointInventoryProvider
{
    private const string Uninstall = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    public static readonly string[] Capabilities = [.. Protocol.RequiredSources, "autoruns", "scheduledTasks"];

    public Inventory Collect(CancellationToken cancellationToken)
    {
        var scan = new Scan(cancellationToken);
        scan.Read("machineRegistry", source =>
        {
            foreach (var view in Views())
            {
                using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                ReadUninstall(root, Uninstall, source);
            }
        });
        scan.Read("userRegistry", source =>
        {
            foreach (var view in Views())
            {
                using var root = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
                var profiles = root.GetSubKeyNames().Where(IsLoadedProfile).ToArray();
                foreach (var profile in profiles)
                    ReadUninstall(root, profile + @"\" + Uninstall, source);
                if (profiles.Length == 0)
                    source.Warn("Нет загруженных пользовательских профилей");
            }
        });
        scan.Read("services", ReadServices);
        scan.Read("processes", ReadProcesses);
        scan.Read("autoruns", ReadAutoruns);
        scan.Read("scheduledTasks", ReadScheduledTasks);
        return new Inventory(Protocol.Version, Guid.NewGuid(), DateTimeOffset.UtcNow, [.. scan.Coverage],
            [.. scan.Observations]);
    }

    private static RegistryView[] Views() => Environment.Is64BitOperatingSystem
        ? [RegistryView.Registry64, RegistryView.Registry32] : [RegistryView.Default];

    private static bool IsLoadedProfile(string name) => name.StartsWith("S-1-", StringComparison.Ordinal) &&
        name is not ("S-1-5-18" or "S-1-5-19" or "S-1-5-20") &&
        name.All(character => char.IsAsciiDigit(character) || character is 'S' or '-');

    private static void ReadUninstall(RegistryKey root, string path, Source source)
    {
        using var uninstall = root.OpenSubKey(path);
        if (uninstall is null)
            return;
        foreach (var key in uninstall.GetSubKeyNames())
        {
            if (!source.CanRead())
                break;
            source.Try(() =>
            {
                using var item = uninstall.OpenSubKey(key);
                if (item?.GetValue("DisplayName") is string name)
                    source.Add(new Observation("registry", name, Publisher: item.GetValue("Publisher") as string,
                        Version: item.GetValue("DisplayVersion") as string));
            });
        }
    }

    private static void ReadServices(Source source)
    {
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services")
            ?? throw new IOException();
        foreach (var name in services.GetSubKeyNames())
        {
            if (!source.CanRead())
                break;
            source.Try(() =>
            {
                using var key = services.OpenSubKey(name);
                if (key?.GetValue("Type") is not int type || (type & 0x30) == 0)
                    return;
                var imagePath = key.GetValue("ImagePath") as string;
                var path = GetExecutable(imagePath);
                source.Add(ReadFileMetadata("service", name, path, source));
            });
        }
    }

    private static string? GetExecutable(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
            return null;
        var expanded = Environment.ExpandEnvironmentVariables(imagePath.Trim());
        if (expanded.StartsWith('"'))
        {
            var endQuote = expanded.IndexOf('"', 1);
            return endQuote > 1 ? expanded[1..endQuote] : null;
        }
        var end = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        while (end >= 0)
        {
            if (end + 4 == expanded.Length || char.IsWhiteSpace(expanded[end + 4]))
                return expanded[..(end + 4)];
            end = expanded.IndexOf(".exe", end + 4, StringComparison.OrdinalIgnoreCase);
        }
        return null;
    }

    private static void ReadProcesses(Source source)
    {
        var processes = Process.GetProcesses();
        try
        {
            foreach (var process in processes)
            {
                if (!source.CanRead())
                    break;
                if (process.Id is 0 or 4)
                    continue;
                source.Try(() =>
                {
                    var name = process.ProcessName;
                    string? path = null;
                    try
                    {
                        path = process.MainModule?.FileName;
                    }
                    catch (Win32Exception error) when (error.NativeErrorCode is 87 or 299 or 1168 && HasExited(process))
                    {
                        return;
                    }
                    catch (InvalidOperationException) when (HasExited(process))
                    {
                        return;
                    }
                    catch (Win32Exception)
                    {
                        source.Warn("Пути части процессов недоступны");
                    }
                    source.Add(ReadFileMetadata("process", name, path, source));
                });
            }
        }
        finally
        {
            foreach (var process in processes)
                process.Dispose();
        }
    }

    private static bool HasExited(Process process)
    {
        try { return process.HasExited; }
        catch (Win32Exception) { return false; }
        catch (InvalidOperationException) { return true; }
    }

    private static Observation ReadFileMetadata(string kind, string name, string? path, Source source)
    {
        // Do not open network paths, device namespaces, or local reparse points.
        if (path is null || path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' ||
            path[2] != '\\' || path[3..].Contains(':') ||
            path[3..].Split('\\', '/').Any(segment => segment is "." or ".."))
        {
            if (path is not null)
                source.Warn("Метаданные части файлов пропущены");
            return new Observation(kind, name);
        }

        var observation = new Observation(kind, name, path);
        source.Try(() =>
        {
            if (new DriveInfo(Path.GetPathRoot(path)!).DriveType != DriveType.Fixed)
            {
                source.Warn("Метаданные части файлов пропущены");
                return;
            }
            for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                {
                    source.Warn("Метаданные части файлов пропущены");
                    return;
                }
            }
            var info = FileVersionInfo.GetVersionInfo(path);
            observation = observation with
            {
                Publisher = info.CompanyName, Product = info.ProductName,
                OriginalFilename = info.OriginalFilename, Version = info.ProductVersion
            };
        });
        return observation;
    }

    private sealed class Scan(CancellationToken ct)
    {
        public List<Observation> Observations { get; } = [];
        public List<Coverage> Coverage { get; } = [];

        public void Read(string name, Action<Source> read)
        {
            var source = new Source(this, ct);
            var previous = Observations.Count;
            var readable = source.Try(() => read(source));
            var reason = string.Join(". ", source.Reasons);
            Coverage.Add(new Coverage(name, !readable && Observations.Count == previous ? "unavailable" :
                source.Reasons.Count == 0 ? "complete" : "partial", Observations.Count - previous,
                reason.Length == 0 ? null : reason[..Math.Min(200, reason.Length)]));
        }
    }

    private sealed class Source(Scan scan, CancellationToken ct)
    {
        public HashSet<string> Reasons { get; } = [];
        public void Warn(string reason) => Reasons.Add(reason);

        public bool CanRead()
        {
            ct.ThrowIfCancellationRequested();
            if (scan.Observations.Count < Protocol.MaxObservations)
                return true;
            Warn("Достигнут лимит инвентаризации");
            return false;
        }

        public bool Try(Action read)
        {
            try
            {
                read();
                return true;
            }
            catch (Exception error) when (error is SecurityException or UnauthorizedAccessException or IOException
                or Win32Exception or InvalidOperationException or ArgumentException or NotSupportedException or COMException)
            {
                Warn("Часть данных источника недоступна");
                return false;
            }
        }

        public void Add(Observation observation)
        {
            var name = Clean(observation.Name, 512);
            if (name is null)
                return;
            scan.Observations.Add(observation with
            {
                Name = name, Path = Clean(observation.Path, 1024), Publisher = Clean(observation.Publisher, 256),
                Product = Clean(observation.Product, 256), OriginalFilename = Clean(observation.OriginalFilename, 256),
                Version = Clean(observation.Version, 128)
            });
        }

        private static string? Clean(string? value, int limit)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;
            var clean = string.Concat(value.Where(character => !char.IsControl(character))).Trim();
            if (clean.Length == 0)
                return null;
            if (clean.Length <= limit)
                return clean;
            return clean[..(char.IsHighSurrogate(clean[limit - 1]) ? limit - 1 : limit)];
        }
    }
}
