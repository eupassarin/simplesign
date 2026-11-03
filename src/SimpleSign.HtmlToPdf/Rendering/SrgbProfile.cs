// Licensed to SimpleSign under the MIT License.

using System.Buffers.Binary;
using System.Text;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Builds a compact ICC v2 display profile approximating sRGB (D50-adapted primaries, gamma 2.2),
/// used as the PDF/A output intent. Generated in code so the library ships no binary assets.
/// </summary>
internal static class SrgbProfile
{
    private static readonly Lazy<byte[]> Profile = new(Build);

    /// <summary>Gets the profile bytes.</summary>
    internal static byte[] Bytes => Profile.Value;

    private static byte[] Build()
    {
        var tags = new List<(string Signature, byte[] Data)>
        {
            ("desc", Description("sRGB IEC61966-2.1")),
            ("cprt", Text("No copyright, use freely")),
            ("wtpt", Xyz(0.9642, 1.0, 0.8249)),
            ("rXYZ", Xyz(0.4361, 0.2225, 0.0139)),
            ("gXYZ", Xyz(0.3851, 0.7169, 0.0971)),
            ("bXYZ", Xyz(0.1431, 0.0606, 0.7141)),
        };
        byte[] curve = Curve(2.2);
        tags.Add(("rTRC", curve));
        tags.Add(("gTRC", curve));
        tags.Add(("bTRC", curve));

        int tableSize = 4 + (tags.Count * 12);
        int offset = 128 + tableSize;
        using var data = new MemoryStream();
        var table = new byte[tableSize];
        BinaryPrimitives.WriteUInt32BigEndian(table, (uint)tags.Count);
        var written = new Dictionary<byte[], int>(ReferenceEqualityComparer.Instance);
        for (int i = 0; i < tags.Count; i++)
        {
            (string signature, byte[] payload) = tags[i];
            if (!written.TryGetValue(payload, out int payloadOffset))
            {
                payloadOffset = offset + (int)data.Length;
                data.Write(payload);
                while (data.Length % 4 != 0)
                {
                    data.WriteByte(0);
                }

                written[payload] = payloadOffset;
            }

            int entry = 4 + (i * 12);
            Encoding.ASCII.GetBytes(signature).CopyTo(table, entry);
            BinaryPrimitives.WriteUInt32BigEndian(table.AsSpan(entry + 4), (uint)payloadOffset);
            BinaryPrimitives.WriteUInt32BigEndian(table.AsSpan(entry + 8), (uint)payload.Length);
        }

        byte[] body = data.ToArray();
        byte[] profile = new byte[128 + tableSize + body.Length];
        Span<byte> header = profile.AsSpan(0, 128);
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)profile.Length);
        BinaryPrimitives.WriteUInt32BigEndian(header[8..], 0x02100000); // version 2.1
        Encoding.ASCII.GetBytes("mntr").CopyTo(header[12..]);
        Encoding.ASCII.GetBytes("RGB ").CopyTo(header[16..]);
        Encoding.ASCII.GetBytes("XYZ ").CopyTo(header[20..]);
        // Creation date/time: 2024-01-01 00:00:00
        BinaryPrimitives.WriteUInt16BigEndian(header[24..], 2024);
        BinaryPrimitives.WriteUInt16BigEndian(header[26..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(header[28..], 1);
        Encoding.ASCII.GetBytes("acsp").CopyTo(header[36..]);
        // Rendering intent 0 (perceptual) at 64; PCS illuminant D50 at 68.
        WriteS15Fixed16(header[68..], 0.9642);
        WriteS15Fixed16(header[72..], 1.0);
        WriteS15Fixed16(header[76..], 0.8249);
        table.CopyTo(profile, 128);
        body.CopyTo(profile, 128 + tableSize);
        return profile;
    }

    private static byte[] Xyz(double x, double y, double z)
    {
        var bytes = new byte[20];
        Encoding.ASCII.GetBytes("XYZ ").CopyTo(bytes, 0);
        WriteS15Fixed16(bytes.AsSpan(8), x);
        WriteS15Fixed16(bytes.AsSpan(12), y);
        WriteS15Fixed16(bytes.AsSpan(16), z);
        return bytes;
    }

    private static byte[] Curve(double gamma)
    {
        var bytes = new byte[14];
        Encoding.ASCII.GetBytes("curv").CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), (ushort)Math.Round(gamma * 256));
        return bytes;
    }

    private static byte[] Text(string text)
    {
        byte[] ascii = Encoding.ASCII.GetBytes(text + "\0");
        var bytes = new byte[8 + ascii.Length];
        Encoding.ASCII.GetBytes("text").CopyTo(bytes, 0);
        ascii.CopyTo(bytes, 8);
        return bytes;
    }

    private static byte[] Description(string text)
    {
        byte[] ascii = Encoding.ASCII.GetBytes(text + "\0");
        // 'desc' + reserved + ASCII count + ASCII + Unicode lang/count + ScriptCode code/count/67 bytes
        var bytes = new byte[12 + ascii.Length + 8 + 3 + 67];
        Encoding.ASCII.GetBytes("desc").CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), (uint)ascii.Length);
        ascii.CopyTo(bytes, 12);
        return bytes;
    }

    private static void WriteS15Fixed16(Span<byte> target, double value) =>
        BinaryPrimitives.WriteInt32BigEndian(target, (int)Math.Round(value * 65536));
}
