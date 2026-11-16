using System.Net;
using System.Net.Sockets;
using Microsoft.VisualBasic.FileIO;

namespace LanGuard.Desktop;

internal sealed class DeviceNames
{
    private readonly ILookup<IPAddress?, Lease> byIp;
    private readonly ILookup<string?, Lease> byMac;

    private DeviceNames(Lease[] leases)
    {
        Count = leases.Length;
        byIp = leases.Where(lease => lease.Ip is not null).ToLookup(lease => lease.Ip);
        byMac = leases.Where(lease => lease.Mac is not null).ToLookup(lease => lease.Mac);
    }

    public int Count { get; }

    public static DeviceNames Load(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > 2 * 1024 * 1024)
            throw new InvalidDataException("Допустимый размер CSV — до 2 МБ.");
        using var reader = new StreamReader(stream);
        var header = reader.ReadLine();
        if (header is not null)
        {
            foreach (var delimiter in new[] { ",", ";", "\t" })
            {
                using var headerParser = CreateParser(new StringReader(header), delimiter);
                string[] fields;
                try { fields = headerParser.ReadFields() ?? []; }
                catch (MalformedLineException) { continue; }
                var name = Column(fields, "name", "hostname", "host name", "имя", "имя компьютера");
                var ip = Column(fields, "ip", "ipaddress", "ip address", "ip-адрес");
                var mac = Column(fields, "mac", "macaddress", "mac address", "clientid", "mac-адрес");
                if (name >= 0 && (ip >= 0 || mac >= 0))
                    return LoadRows(reader, delimiter, name, ip, mac);
            }
        }
        throw new InvalidDataException("В CSV нужны столбец name (или HostName) и хотя бы один из столбцов ip и mac.");
    }

    public HostIdentity? Find(IPAddress address, string? mac)
    {
        mac = NormalizeMac(mac);
        var name = mac is null ? null : UniqueName(byMac[mac]);
        if (name is not null)
            return new HostIdentity(name, "CSV");

        var candidates = byIp[address];
        if (mac is null)
            name = UniqueName(candidates);
        else if (candidates.Any(lease => lease.Mac is not null))
            name = UniqueName(candidates.Where(lease => lease.Mac == mac));
        else
            name = UniqueName(candidates);
        return name is null ? null : new HostIdentity(name, "CSV");
    }

    private static DeviceNames LoadRows(TextReader reader, string delimiter, int nameColumn, int ipColumn, int macColumn)
    {
        var leases = new HashSet<Lease>();
        using var parser = CreateParser(reader, delimiter);
        while (!parser.EndOfData)
        {
            var fields = parser.ReadFields() ?? [];
            var name = Field(fields, nameColumn)?.Trim().TrimEnd('.');
            if (name is not { Length: > 0 and <= 253 } || name.Any(char.IsControl) || IPAddress.TryParse(name, out _))
                continue;
            var mac = NormalizeMac(Field(fields, macColumn));
            IPAddress? ip = IPAddress.TryParse(Field(fields, ipColumn), out var address) &&
                address.AddressFamily == AddressFamily.InterNetwork ? address : null;
            if (ip is not null || mac is not null)
                leases.Add(new Lease(ip, mac, name));
        }
        return new DeviceNames([.. leases]);
    }

    private static TextFieldParser CreateParser(TextReader reader, string delimiter) => new(reader)
    {
        TextFieldType = FieldType.Delimited, Delimiters = [delimiter], HasFieldsEnclosedInQuotes = true
    };

    private static int Column(string[] fields, params string[] aliases) =>
        Array.FindIndex(fields, field => aliases.Contains(field.Trim(), StringComparer.OrdinalIgnoreCase));

    private static string? Field(string[] fields, int index) =>
        index >= 0 && index < fields.Length ? fields[index] : null;

    private static string? NormalizeMac(string? mac)
    {
        var compact = mac?.Trim().Replace(":", "").Replace("-", "").Replace(".", "");
        return compact is { Length: 12 } && compact.All(Uri.IsHexDigit) ? compact.ToUpperInvariant() : null;
    }

    private static string? UniqueName(IEnumerable<Lease> leases)
    {
        var names = leases.Select(lease => lease.Name).Distinct(StringComparer.OrdinalIgnoreCase).Take(2).ToArray();
        return names.Length == 1 ? names[0] : null;
    }

    private sealed record Lease(IPAddress? Ip, string? Mac, string Name);
}
