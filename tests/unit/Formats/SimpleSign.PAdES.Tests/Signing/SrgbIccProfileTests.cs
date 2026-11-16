using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for <see cref="SrgbIccProfile"/>: the header and tags PDF/A validators read (ISO 19005-1 §6.2.3,
/// ISO 19005-2 §6.2.4.2) and the stream object a stamp references.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SrgbIccProfileTests
{
    [Theory(DisplayName = "Profile header: size, version 2.1, monitor class, colour space, XYZ PCS, acsp, D50")]
    [InlineData(true, "RGB ")]
    [InlineData(false, "GRAY")]
    public void Profile_Header_IsValidVersion2Display(bool rgb, string colorSpace)
    {
        byte[] profile = (rgb ? SrgbIccProfile.Rgb : SrgbIccProfile.Gray).ToArray();

        BinaryPrimitives.ReadUInt32BigEndian(profile).ShouldBe((uint)profile.Length);
        profile[8].ShouldBe((byte)2);
        profile[9].ShouldBe((byte)0x10);
        Ascii(profile, 12).ShouldBe("mntr");
        Ascii(profile, 16).ShouldBe(colorSpace);
        Ascii(profile, 20).ShouldBe("XYZ ");
        Ascii(profile, 36).ShouldBe("acsp");
        BinaryPrimitives.ReadInt32BigEndian(profile.AsSpan(68)).ShouldBe(0xF6D6);
        BinaryPrimitives.ReadInt32BigEndian(profile.AsSpan(72)).ShouldBe(0x10000);
        BinaryPrimitives.ReadInt32BigEndian(profile.AsSpan(76)).ShouldBe(0xD32D);
    }

    [Theory(DisplayName = "Profile tags: the required tags of a matrix/TRC (or gray TRC) display profile, all in bounds")]
    [InlineData(true, new[] { "desc", "cprt", "wtpt", "rXYZ", "gXYZ", "bXYZ", "rTRC", "gTRC", "bTRC" })]
    [InlineData(false, new[] { "desc", "cprt", "wtpt", "kTRC" })]
    public void Profile_Tags_AreRequiredSetAndInBounds(bool rgb, string[] expected)
    {
        byte[] profile = (rgb ? SrgbIccProfile.Rgb : SrgbIccProfile.Gray).ToArray();

        var tags = Tags(profile);

        tags.Keys.ShouldBe(expected, ignoreOrder: true);
        foreach (var (offset, size) in tags.Values)
        {
            (offset % 4).ShouldBe(0);
            (offset + size).ShouldBeLessThanOrEqualTo(profile.Length);
        }
    }

    [Fact(DisplayName = "Tone curve: sRGB transfer function from 0 to 1, rising")]
    public void Profile_ToneCurve_IsSrgbTransferFunction()
    {
        byte[] profile = SrgbIccProfile.Rgb.ToArray();
        var (offset, _) = Tags(profile)["rTRC"];

        Ascii(profile, offset).ShouldBe("curv");
        int count = (int)BinaryPrimitives.ReadUInt32BigEndian(profile.AsSpan(offset + 8));
        count.ShouldBe(SrgbIccProfile.CurvePoints);
        ushort Sample(int i) => BinaryPrimitives.ReadUInt16BigEndian(profile.AsSpan(offset + 12 + (i * 2)));
        Sample(0).ShouldBe((ushort)0);
        Sample(count - 1).ShouldBe(ushort.MaxValue);
        // Code value 128 (sRGB 50 % gray) is about 21.6 % linear light (IEC 61966-2-1).
        (Sample(128) / 65535.0).ShouldBe(Math.Pow(((128 / 255.0) + 0.055) / 1.055, 2.4), 1e-5);
        (Sample(10) / 65535.0).ShouldBe(10 / 255.0 / 12.92, 1e-5);
        var samples = Enumerable.Range(0, count).Select(Sample).ToArray();
        samples.ShouldBe([.. samples.Order()]);
    }

    [Fact(DisplayName = "Shared tone curve: rTRC, gTRC and bTRC point at the same data")]
    public void Profile_RgbToneCurves_Shared()
    {
        var tags = Tags(SrgbIccProfile.Rgb.ToArray());

        tags["gTRC"].ShouldBe(tags["rTRC"]);
        tags["bTRC"].ShouldBe(tags["rTRC"]);
    }

    [Theory(DisplayName = "Stream object: /N matches the profile, FlateDecode data inflates to the profile")]
    [InlineData(true, 3)]
    [InlineData(false, 1)]
    public void BuildStreamObject_InflatesToProfile(bool rgb, int components)
    {
        byte[] obj = SrgbIccProfile.BuildStreamObject(42, rgb);
        string text = Encoding.Latin1.GetString(obj);

        text.ShouldStartWith("42 0 obj\n");
        text.ShouldContain($"/N {components}");
        text.ShouldContain("/Filter /FlateDecode");
        text.ShouldEndWith("\nendstream\nendobj\n");
        int length = int.Parse(Regex.Match(text, @"/Length (\d+)").Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        int start = text.IndexOf("stream\n", StringComparison.Ordinal) + "stream\n".Length;
        Inflate(obj[start..(start + length)]).ShouldBe((rgb ? SrgbIccProfile.Rgb : SrgbIccProfile.Gray).ToArray());
    }

    [Fact(DisplayName = "Profile bytes never change between calls")]
    public void BuildStreamObject_Deterministic() =>
        SrgbIccProfile.BuildStreamObject(7, rgb: true).ShouldBe(SrgbIccProfile.BuildStreamObject(7, rgb: true));

    private static Dictionary<string, (int Offset, int Size)> Tags(byte[] profile)
    {
        int count = (int)BinaryPrimitives.ReadUInt32BigEndian(profile.AsSpan(128));
        var tags = new Dictionary<string, (int, int)>(StringComparer.Ordinal);
        for (int i = 0; i < count; i++)
        {
            int entry = 132 + (i * 12);
            tags[Ascii(profile, entry)] = (
                (int)BinaryPrimitives.ReadUInt32BigEndian(profile.AsSpan(entry + 4)),
                (int)BinaryPrimitives.ReadUInt32BigEndian(profile.AsSpan(entry + 8)));
        }

        return tags;
    }

    private static string Ascii(byte[] data, int offset) => Encoding.ASCII.GetString(data, offset, 4);

    private static byte[] Inflate(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return output.ToArray();
    }
}
