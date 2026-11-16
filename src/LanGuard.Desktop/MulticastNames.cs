using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace LanGuard.Desktop;

internal static class MulticastNames
{
    private const ushort PtrType = 12;
    private const ushort InternetClass = 1;
    private static readonly IPEndPoint Mdns = new(IPAddress.Parse("224.0.0.251"), 5353);
    private static readonly IPEndPoint Llmnr = new(IPAddress.Parse("224.0.0.252"), 5355);

    public static async Task<HostIdentity?> Resolve(IPAddress local, IPAddress target, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromMilliseconds(800));
        var owner = string.Join(".", target.GetAddressBytes().Reverse()) + ".in-addr.arpa";
        var mdns = Query(local, target, Mdns, owner, deadline.Token);
        var llmnr = Query(local, target, Llmnr, owner, deadline.Token);
        var first = await Task.WhenAny(mdns, llmnr);
        var second = first == mdns ? llmnr : mdns;
        var name = await first;
        if (name is not null)
        {
            await deadline.CancelAsync();
            await second;
            ct.ThrowIfCancellationRequested();
            return new HostIdentity(name, first == mdns ? "mDNS" : "LLMNR");
        }

        name = await second;
        ct.ThrowIfCancellationRequested();
        return name is null ? null : new HostIdentity(name, second == mdns ? "mDNS" : "LLMNR");
    }

    private static async Task<string?> Query(IPAddress local, IPAddress target, IPEndPoint group,
        string owner, CancellationToken ct)
    {
        try
        {
            // An ephemeral source port requests a unicast reply, including for legacy mDNS queries.
            using var client = new UdpClient(new IPEndPoint(local, 0));
            client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes());
            client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);
            var transaction = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue + 1);
            await client.SendAsync(BuildPtrQuery(owner, transaction), group, ct);
            while (!ct.IsCancellationRequested)
            {
                var reply = await client.ReceiveAsync(ct);
                if (reply.RemoteEndPoint.Port == group.Port && reply.RemoteEndPoint.Address.Equals(target) &&
                    ReadPtrReply(reply.Buffer, transaction, owner, group.Port == Llmnr.Port) is { } name)
                    return name;
            }
        }
        catch (SocketException) { }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        return null;
    }

    internal static byte[] BuildPtrQuery(string owner, ushort transaction)
    {
        var packet = new byte[12 + owner.Length + 2 + 4];
        BinaryPrimitives.WriteUInt16BigEndian(packet, transaction);
        packet[5] = 1;
        var offset = 12;
        foreach (var label in owner.Split('.'))
        {
            packet[offset++] = (byte)label.Length;
            offset += Encoding.ASCII.GetBytes(label, packet.AsSpan(offset));
        }
        offset++; // Root label.
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset), PtrType);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 2), InternetClass);
        return packet;
    }

    internal static string? ReadPtrReply(byte[] packet, ushort transaction, string expectedOwner, bool llmnr)
    {
        if (packet.Length < 12 || Read16(packet, 0) != transaction)
            return null;
        var rejectedFlags = llmnr ? 0xFF0F : 0xFA0F;
        if ((Read16(packet, 2) & rejectedFlags) != 0x8000)
            return null;
        var offset = 12;
        var questions = Read16(packet, 4);
        for (var i = 0; i < questions; i++)
        {
            if (ReadName(packet, ref offset) is null || packet.Length - offset < 4)
                return null;
            offset += 4;
        }

        var answers = Read16(packet, 6);
        for (var i = 0; i < answers; i++)
        {
            var owner = ReadName(packet, ref offset);
            if (owner is null || packet.Length - offset < 10)
                return null;
            var type = Read16(packet, offset);
            var recordClass = Read16(packet, offset + 2) & 0x7FFF;
            var length = Read16(packet, offset + 8);
            offset += 10;
            if (length > packet.Length - offset)
                return null;
            if (type == PtrType && recordClass == InternetClass && length > 0 &&
                expectedOwner.Equals(owner, StringComparison.OrdinalIgnoreCase))
            {
                var end = offset + length;
                var name = ReadName(packet, ref offset);
                return offset == end ? HostNames.Clean(name) : null;
            }
            offset += length;
        }
        return null;
    }

    private static string? ReadName(byte[] packet, ref int offset)
    {
        var labels = new List<string>();
        var cursor = offset;
        var jumped = false;
        var length = 0;
        while (cursor < packet.Length)
        {
            var label = packet[cursor++];
            if (label == 0)
            {
                if (!jumped)
                    offset = cursor;
                return string.Join(".", labels);
            }
            if ((label & 0xC0) == 0xC0)
            {
                if (cursor >= packet.Length)
                    return null;
                var pointer = ((label & 0x3F) << 8) | packet[cursor++];
                // DNS compression references an earlier label.
                if (pointer < 12 || pointer >= cursor - 2)
                    return null;
                if (!jumped)
                    offset = cursor;
                jumped = true;
                cursor = pointer;
                continue;
            }
            length += label + 1;
            if (label > 63 || label > packet.Length - cursor || length > 254)
                return null;
            labels.Add(Encoding.UTF8.GetString(packet, cursor, label));
            cursor += label;
        }
        return null;
    }

    private static ushort Read16(byte[] packet, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset));
}
