using System.Runtime.InteropServices;

namespace LanGuard.Desktop;

internal sealed record PublishedShare(string Name, string Kind, string? Description, bool Hidden);
internal sealed record ShareDetails(PublishedShare[] Items, string Status);

internal static partial class NetworkShares
{
    private const uint Success = 0;
    private const uint MoreData = 234;
    private const int Limit = 256;

    public static ShareDetails Read(string? target)
    {
        var shares = new List<PublishedShare>();
        var server = target is null ? null : @"\\" + target;
        uint resume = 0;
        for (var page = 0; page < 4; page++)
        {
            var previous = resume;
            var code = NetShareEnum(server, 1, out var buffer, 32 * 1024, out var count, out _, ref resume);
            try
            {
                if (code is not (Success or MoreData))
                {
                    var message = code == 5 ? "Отказано в доступе к списку общих ресурсов SMB." :
                        $"Список общих ресурсов SMB недоступен (код Windows {code}).";
                    return new ShareDetails([.. shares], message);
                }

                var size = Marshal.SizeOf<ShareInfo>();
                for (var i = 0; buffer != 0 && i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<ShareInfo>(buffer + i * size);
                    var type = entry.Type & 0xFF;
                    if (type is not (0 or 1) || Clean(Marshal.PtrToStringUni(entry.Name)) is not { } name)
                        continue;
                    shares.Add(new PublishedShare(name, type == 0 ? "Папка" : "Принтер",
                        Clean(Marshal.PtrToStringUni(entry.Remark)), name.EndsWith('$') || (entry.Type & 0x80000000) != 0));
                    if (shares.Count == Limit)
                        return new ShareDetails([.. shares], "Показаны первые 256 общих ресурсов.");
                }
            }
            finally
            {
                if (buffer != 0)
                    _ = NetApiBufferFree(buffer);
            }
            if (code == Success)
                return new ShareDetails([.. shares], "Список общих ресурсов SMB получен.");
            if (resume == previous)
                break;
        }
        return new ShareDetails([.. shares], "Список общих ресурсов SMB получен частично.");
    }

    internal static string? Clean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var clean = string.Concat(value.Where(character => !char.IsControl(character)).Take(512)).Trim();
        return clean.Length == 0 ? null : clean;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ShareInfo
    {
        public nint Name;
        public uint Type;
        public nint Remark;
    }

    [LibraryImport("Netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint NetShareEnum(string? server, uint level, out nint buffer, uint preferredLength,
        out uint entriesRead, out uint totalEntries, ref uint resume);

    [LibraryImport("Netapi32.dll")]
    private static partial uint NetApiBufferFree(nint buffer);
}
