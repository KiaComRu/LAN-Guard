using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace LanGuard.Desktop;

internal sealed record ScanNetwork(string Adapter, IPAddress LocalIp, int Prefix, bool HasGateway)
{
    private uint Network => AddressNumber(LocalIp) & Mask(Prefix);
    public string DefaultRange => $"{Address(AddressNumber(LocalIp) & Mask(Math.Max(Prefix, 22)))}/{Math.Max(Prefix, 22)}";
    public override string ToString() => $"{Adapter}  •  {LocalIp}/{Prefix}";

    public bool Contains(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork)
            return false;
        var address = AddressNumber(ip);
        return (address & Mask(Prefix)) == Network && Usable(address, Network, Prefix);
    }

    public bool TryGetTargets(string input, out IPAddress[] targets)
    {
        targets = [];
        var parts = input.Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != parts[0] ||
            !int.TryParse(parts[1], out var prefix) || prefix < Math.Max(Prefix, 22) || prefix > 32)
            return false;
        var mask = Mask(prefix);
        var first = AddressNumber(ip) & mask;
        var last = first | ~mask;
        if ((first & Mask(Prefix)) != Network || first != AddressNumber(ip))
            return false;
        targets = Enumerable.Range(0, checked((int)(last - first + 1)))
            .Select(offset => first + (uint)offset)
            .Where(address => Usable(address, first, prefix) && Usable(address, Network, Prefix))
            .Select(Address).ToArray();
        return targets.Length > 0;
    }

    public static ScanNetwork[] All() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up &&
            adapter.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211
                or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetFx
                or NetworkInterfaceType.FastEthernetT)
        .SelectMany(adapter =>
        {
            var properties = adapter.GetIPProperties();
            var gateway = properties.GatewayAddresses.Any(entry =>
                entry.Address.AddressFamily == AddressFamily.InterNetwork && !entry.Address.Equals(IPAddress.Any));
            return properties.UnicastAddresses.Where(entry =>
                    entry.Address.AddressFamily == AddressFamily.InterNetwork && entry.PrefixLength is > 0 and <= 32)
                .Select(entry => new ScanNetwork(adapter.Name, entry.Address, entry.PrefixLength, gateway));
        })
        .OrderByDescending(network => network.HasGateway)
        .ThenBy(network => network.Adapter).ToArray();

    public static uint AddressNumber(IPAddress address) => BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
    private static IPAddress Address(uint address)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, address);
        return new IPAddress(bytes);
    }

    private static uint Mask(int prefix) => uint.MaxValue << (32 - prefix);
    private static bool Usable(uint address, uint first, int prefix) => prefix >= 31 ||
        (address != first && address != (first | ~Mask(prefix)));
}
