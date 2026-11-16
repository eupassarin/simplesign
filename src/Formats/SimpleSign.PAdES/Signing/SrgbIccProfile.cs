using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// ICC profiles for sRGB and for gray with the sRGB tone curve, built in code (ICC.1:2001-04, version 2.1).
/// A signature stamp on a PDF/A document names them as <c>/DefaultRGB</c> and <c>/DefaultGray</c>, so its
/// DeviceRGB and DeviceGray painting is device-independent (ISO 19005-1 §6.2.3.3, ISO 19005-2/3 §6.2.4.3).
/// </summary>
/// <remarks>
/// SimpleSign writes these profiles itself instead of shipping a third-party <c>.icc</c> file, so no licence
/// comes with them. They are matrix/TRC display profiles: the IEC 61966-2-1 primaries adapted to D50 (the values
/// of the ICC's own sRGB profiles) and the sRGB transfer function sampled at <see cref="CurvePoints"/> points.
/// Version 2.1 is accepted by every PDF/A part: PDF/A-1 (PDF 1.4) reads ICC profiles before version 4 only.
/// </remarks>
internal static class SrgbIccProfile
{
    /// <summary>
    /// Number of samples of the sRGB transfer function in each tone curve: one per 8-bit code value, so the
    /// stamp's colours (and 8-bit images) fall exactly on a sample.
    /// </summary>
    internal const int CurvePoints = 256;

    private const int HeaderSize = 128;
    private const int TagEntrySize = 12;

    // D50, the ICC profile connection space illuminant, in XYZ.
    private static readonly double[] D50 = [0.9642, 1.0, 0.8249];

    // IEC 61966-2-1 sRGB primaries, chromatically adapted to D50 (Bradford), as in the ICC's sRGB profiles.
    private static readonly double[] Red = [0.436066, 0.222488, 0.013916];
    private static readonly double[] Green = [0.385147, 0.716873, 0.097076];
    private static readonly double[] Blue = [0.143066, 0.060608, 0.714096];

    private static readonly Lazy<byte[]> RgbProfile = new(() => Build(rgb: true));
    private static readonly Lazy<byte[]> GrayProfile = new(() => Build(rgb: false));
    private static readonly Lazy<byte[]> RgbDeflated = new(() => Deflate(RgbProfile.Value));
    private static readonly Lazy<byte[]> GrayDeflated = new(() => Deflate(GrayProfile.Value));

    /// <summary>The sRGB profile (three components, device class <c>mntr</c>).</summary>
    internal static ReadOnlySpan<byte> Rgb => RgbProfile.Value;

    /// <summary>The gray profile with the sRGB tone curve (one component, device class <c>mntr</c>).</summary>
    internal static ReadOnlySpan<byte> Gray => GrayProfile.Value;

    /// <summary>
    /// Writes one profile as an indirect <c>/ICCBased</c> stream object (FlateDecode), for a
    /// <c>[/ICCBased n 0 R]</c> colour space.
    /// </summary>
    /// <param name="objNum">Object number of the stream.</param>
    /// <param name="rgb">True for the sRGB profile (<c>/N 3</c>), false for the gray profile (<c>/N 1</c>).</param>
    internal static byte[] BuildStreamObject(int objNum, bool rgb)
    {
        byte[] data = rgb ? RgbDeflated.Value : GrayDeflated.Value;
        string header = $"{objNum} 0 obj\n<< /N {(rgb ? 3 : 1)}\n   /Filter /FlateDecode\n   /Length {data.Length}\n>>\nstream\n";
        byte[] headerBytes = Encoding.Latin1.GetBytes(header);
        ReadOnlySpan<byte> trailer = "\nendstream\nendobj\n"u8;

        byte[] result = new byte[headerBytes.Length + data.Length + trailer.Length];
        headerBytes.CopyTo(result, 0);
        data.CopyTo(result, headerBytes.Length);
        trailer.CopyTo(result.AsSpan(headerBytes.Length + data.Length));
        return result;
    }

    private static byte[] Build(bool rgb)
    {
        byte[] desc = TextDescription(rgb ? "SimpleSign sRGB" : "SimpleSign sRGB gray");
        byte[] cprt = Text("No copyright, use freely");
        byte[] wtpt = Xyz(D50);
        byte[] curve = SrgbCurve();

        // Tag data in table order; the three RGB tone curves share one curve (ICC.1 §6.4 allows shared data).
        var tags = new List<(string Signature, byte[] Data)> { ("desc", desc), ("cprt", cprt), ("wtpt", wtpt) };
        if (rgb)
        {
            tags.Add(("rXYZ", Xyz(Red)));
            tags.Add(("gXYZ", Xyz(Green)));
            tags.Add(("bXYZ", Xyz(Blue)));
            tags.Add(("rTRC", curve));
            tags.Add(("gTRC", curve));
            tags.Add(("bTRC", curve));
        }
        else
        {
            tags.Add(("kTRC", curve));
        }

        int offset = Align4(HeaderSize + 4 + (tags.Count * TagEntrySize));
        var placed = new List<(string Signature, int Offset, int Size)>();
        var dataOffsets = new Dictionary<byte[], int>(ReferenceEqualityComparer.Instance);
        foreach (var (signature, data) in tags)
        {
            if (!dataOffsets.TryGetValue(data, out int at))
            {
                at = offset;
                dataOffsets[data] = at;
                offset = Align4(offset + data.Length);
            }

            placed.Add((signature, at, data.Length));
        }

        byte[] profile = new byte[offset];
        Span<byte> p = profile;

        // Header (ICC.1 §6.1).
        BinaryPrimitives.WriteUInt32BigEndian(p, (uint)profile.Length);
        BinaryPrimitives.WriteUInt32BigEndian(p[8..], 0x02100000); // version 2.1.0
        Ascii(p[12..], "mntr");
        Ascii(p[16..], rgb ? "RGB " : "GRAY");
        Ascii(p[20..], "XYZ ");
        // Fixed creation date (2026-01-01 00:00:00), so the profile bytes never change.
        BinaryPrimitives.WriteUInt16BigEndian(p[24..], 2026);
        BinaryPrimitives.WriteUInt16BigEndian(p[26..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(p[28..], 1);
        Ascii(p[36..], "acsp");
        // Rendering intent 0 (perceptual) at 64; PCS illuminant at 68.
        WriteXyzNumber(p[68..], D50);

        // Tag table.
        BinaryPrimitives.WriteUInt32BigEndian(p[HeaderSize..], (uint)placed.Count);
        int entry = HeaderSize + 4;
        foreach (var (signature, at, size) in placed)
        {
            Ascii(p[entry..], signature);
            BinaryPrimitives.WriteUInt32BigEndian(p[(entry + 4)..], (uint)at);
            BinaryPrimitives.WriteUInt32BigEndian(p[(entry + 8)..], (uint)size);
            entry += TagEntrySize;
        }

        foreach (var (data, at) in dataOffsets)
        {
            data.CopyTo(p[at..]);
        }

        return profile;
    }

    /// <summary>textDescriptionType (ICC.1:2001-04 §6.5.17): ASCII, an empty Unicode and an empty ScriptCode part.</summary>
    private static byte[] TextDescription(string text)
    {
        int asciiCount = text.Length + 1;
        byte[] data = new byte[12 + asciiCount + 8 + 3 + 67];
        Ascii(data, "desc");
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), (uint)asciiCount);
        Ascii(data.AsSpan(12), text);
        return data;
    }

    /// <summary>textType (ICC.1:2001-04 §6.5.18): NUL-terminated ASCII.</summary>
    private static byte[] Text(string text)
    {
        byte[] data = new byte[8 + text.Length + 1];
        Ascii(data, "text");
        Ascii(data.AsSpan(8), text);
        return data;
    }

    /// <summary>XYZType (ICC.1:2001-04 §6.5.26) with one XYZ number.</summary>
    private static byte[] Xyz(double[] xyz)
    {
        byte[] data = new byte[20];
        Ascii(data, "XYZ ");
        WriteXyzNumber(data.AsSpan(8), xyz);
        return data;
    }

    /// <summary>curveType (ICC.1:2001-04 §6.5.3) sampling the sRGB transfer function (IEC 61966-2-1).</summary>
    private static byte[] SrgbCurve()
    {
        byte[] data = new byte[12 + (CurvePoints * 2)];
        Ascii(data, "curv");
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), CurvePoints);
        for (int i = 0; i < CurvePoints; i++)
        {
            double v = (double)i / (CurvePoints - 1);
            double linear = v <= 0.04045 ? v / 12.92 : Math.Pow((v + 0.055) / 1.055, 2.4);
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(12 + (i * 2)), (ushort)Math.Round(linear * ushort.MaxValue));
        }

        return data;
    }

    private static void WriteXyzNumber(Span<byte> destination, double[] xyz)
    {
        for (int i = 0; i < 3; i++)
        {
            // s15Fixed16Number (ICC.1 §5.3.1).
            BinaryPrimitives.WriteInt32BigEndian(destination[(i * 4)..], (int)Math.Round(xyz[i] * 65536));
        }
    }

    private static void Ascii(Span<byte> destination, string text) => Encoding.ASCII.GetBytes(text, destination);

    private static int Align4(int value) => (value + 3) & ~3;

    private static byte[] Deflate(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new ZLibStream(ms, CompressionLevel.SmallestSize))
        {
            zlib.Write(data);
        }

        return ms.ToArray();
    }
}
