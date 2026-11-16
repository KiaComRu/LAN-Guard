using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace LanGuard.Desktop;

internal sealed record HostIdentity(string Name, string Source);

internal static class HostNames
{
    private const ushort NodeStatus = 0x0021;
    private const ushort InternetClass = 1;

    public static async Task<HostIdentity?> Resolve(IPAddress local, IPAddress target, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromMilliseconds(900));
        using var netBiosDeadline = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        var netBios = ResolveNetBios(local, target, netBiosDeadline.Token);
        try
        {
            // The Windows resolver may finish its native reverse lookup after our deadline.
            var dns = await Dns.GetHostEntryAsync(target.ToString(), AddressFamily.InterNetwork, deadline.Token)
                .WaitAsync(deadline.Token);
            if (Clean(dns.HostName) is { } name)
            {
                await netBiosDeadline.CancelAsync();
                await netBios;
                return new HostIdentity(name, "DNS");
            }
        }
        catch (SocketException) { }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }

        var fallback = await netBios;
        ct.ThrowIfCancellationRequested();
        if (fallback is not null)
            return new HostIdentity(fallback, "NetBIOS");
        return await MulticastNames.Resolve(local, target, ct);
    }

    private static async Task<string?> ResolveNetBios(IPAddress local, IPAddress target, CancellationToken ct)
    {
        try
        {
            using var client = new UdpClient(new IPEndPoint(local, 0));
            client.Connect(target, 137);
            var transaction = (ushort)RandomNumberGenerator.GetInt32(65536);
            await client.SendAsync(BuildNodeStatusQuery(transaction), ct);
            var reply = await client.ReceiveAsync(ct);
            return ReadNodeStatus(reply.Buffer, transaction);
        }
        catch (SocketException) { return null; }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return null; }
    }

    internal static byte[] BuildNodeStatusQuery(ushort transaction)
    {
        var query = new byte[50];
        BinaryPrimitives.WriteUInt16BigEndian(query, transaction);
        query[5] = 1; // One question.
        query[12] = 32;
        // Encode the wildcard NetBIOS name: an asterisk followed by 15 zero bytes.
        query.AsSpan(13, 32).Fill((byte)'A');
        query[13] = (byte)'C';
        query[14] = (byte)'K';
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(46), NodeStatus);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(48), InternetClass);
        return query;
    }

    internal static string? ReadNodeStatus(byte[] packet, ushort transaction)
    {
        if (packet.Length < 12 || Read16(packet, 0) != transaction ||
            (Read16(packet, 2) & 0xFA0F) != 0x8000)
            return null;
        var offset = 12;
        var questions = Read16(packet, 4);
        for (var question = 0; question < questions; question++)
        {
            if (!SkipName(packet, ref offset) || packet.Length - offset < 4)
                return null;
            offset += 4;
        }

        var answers = Read16(packet, 6);
        for (var answer = 0; answer < answers; answer++)
        {
            if (!SkipName(packet, ref offset) || packet.Length - offset < 10)
                return null;
            var type = Read16(packet, offset);
            var recordClass = Read16(packet, offset + 2);
            var length = Read16(packet, offset + 8);
            offset += 10;
            if (length > packet.Length - offset)
                return null;
            if (type == NodeStatus && recordClass == InternetClass && length > 0)
                return ReadWorkstationNames(packet.AsSpan(offset, length));
            offset += length;
        }
        return null;
    }

    private static string? ReadWorkstationNames(ReadOnlySpan<byte> data)
    {
        const int entrySize = 18;
        var count = data[0];
        if (1 + count * entrySize > data.Length)
            return null;
        string? serverName = null;
        for (var i = 0; i < count; i++)
        {
            var entry = data.Slice(1 + i * entrySize, entrySize);
            var suffix = entry[15];
            if ((entry[16] & 0x80) != 0 || suffix is not (0x00 or 0x20) ||
                Clean(Encoding.ASCII.GetString(entry[..15])) is not { } name)
                continue;
            if (suffix == 0x00)
                return name;
            serverName ??= name;
        }
        return serverName;
    }

    private static bool SkipName(byte[] packet, ref int offset)
    {
        while (offset < packet.Length)
        {
            var label = packet[offset++];
            if (label == 0)
                return true;
            if ((label & 0xC0) == 0xC0)
                return offset++ < packet.Length;
            if (label > 63 || label > packet.Length - offset)
                return false;
            offset += label;
        }
        return false;
    }

    private static ushort Read16(byte[] packet, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset));

    internal static string? Clean(string? value)
    {
        var name = value?.Trim().TrimEnd('.');
        return name is { Length: > 0 and <= 253 } && !IPAddress.TryParse(name, out _) &&
            name.All(character => char.IsLetterOrDigit(character) || character is '.' or '-' or '_') &&
            name.Any(char.IsLetterOrDigit) ? name : null;
    }
}
