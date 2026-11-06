// Licensed to SimpleSign under the MIT License.

using System.IO.Compression;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Caches image data as PDF XObject indirect objects.
/// Deduplicates images by source URI and writes them once per document.
/// </summary>
internal sealed class ImageObjectCache
{
    private readonly PdfObjectWriter _writer;
    private readonly Dictionary<string, string?> _sourceToName = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _nameToObjNum = [];
    private readonly Dictionary<string, (int Width, int Height)> _sizes = new(StringComparer.Ordinal);
    private int _counter;

    public ImageObjectCache(PdfObjectWriter writer, ResourceLoader? loader = null)
    {
        _writer = writer;
        Loader = loader ?? ResourceLoader.DataUriOnly;
    }

    /// <summary>Gets the loader used for image sources.</summary>
    public ResourceLoader Loader { get; }

    private readonly Dictionary<string, Parsing.HtmlNode?> _svgDocuments = new(StringComparer.Ordinal);

    /// <summary>Loads (once) an SVG document referenced by an image source; null when it is not SVG.</summary>
    public Parsing.HtmlNode? GetSvg(string source)
    {
        if (!_svgDocuments.TryGetValue(source, out Parsing.HtmlNode? svg))
        {
            svg = Svg.SvgDocument.Load(source, Loader);
            _svgDocuments[source] = svg;
        }

        return svg;
    }

    /// <summary>Gets or creates a PDF image XObject for the given source.</summary>
    /// <returns>Image resource name (e.g., "Img1"), or null if image is invalid.</returns>
    public string? GetOrAdd(string source)
    {
        if (_sourceToName.TryGetValue(source, out string? existing))
        {
            return existing; // null when the image previously failed to decode
        }

        ImageData? img = ImageData.Parse(source, Loader);
        if (img is null || (img.Format == ImageFormat.Png && PngDecoder.Decode(img.Data) is null))
        {
            _sourceToName[source] = null;
            return null;
        }

        _counter++;
        string name = $"Img{_counter}";
        int objNum = _writer.AllocateObject();

        WriteImageXObject(objNum, img);

        _sourceToName[source] = name;
        _nameToObjNum[name] = objNum;
        _sizes[name] = (img.Width, img.Height);
        return name;
    }

    /// <summary>Gets the intrinsic pixel size of a named image.</summary>
    public bool TryGetSize(string name, out int width, out int height)
    {
        bool found = _sizes.TryGetValue(name, out var size);
        (width, height) = size;
        return found;
    }

    /// <summary>Gets the PDF object number for a named image.</summary>
    public bool TryGetObjectNum(string name, out int objNum) => _nameToObjNum.TryGetValue(name, out objNum);

    private void WriteImageXObject(int objNum, ImageData img)
    {
        if (img.Format == ImageFormat.Jpeg)
        {
            WriteJpegXObject(objNum, img);
        }
        else if (img.Format == ImageFormat.Png)
        {
            WritePngXObject(objNum, img);
        }
    }

    private void WriteJpegXObject(int objNum, ImageData img)
    {
        // JPEG: embed raw bytes with DCTDecode
        string colorSpace = img.Components switch
        {
            1 => "/DeviceGray",
            4 => "/DeviceCMYK",
            _ => "/DeviceRGB",
        };

        string decode = img.AdobeInverted ? " /Decode [1 0 1 0 1 0 1 0]" : string.Empty;
        string dict = $"/Type /XObject /Subtype /Image /Width {img.Width} /Height {img.Height} " +
                       $"/ColorSpace {colorSpace} /BitsPerComponent {img.BitsPerComponent}{decode} /Filter /DCTDecode";

        _writer.WriteStreamObject(objNum, dict, img.Data);
    }

    private void WritePngXObject(int objNum, ImageData img)
    {
        DecodedPng? png = PngDecoder.Decode(img.Data);
        if (png is null)
        {
            return;
        }

        string smask = string.Empty;
        if (png.Alpha is not null)
        {
            int maskObj = _writer.AllocateObject();
            string maskDict = $"/Type /XObject /Subtype /Image /Width {png.Width} /Height {png.Height} " +
                              "/ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode";
            _writer.WriteStreamObject(maskObj, maskDict, Deflate(png.Alpha));
            smask = $" /SMask {maskObj} 0 R";
        }

        string colorSpace = png.ColorComponents == 1 ? "/DeviceGray" : "/DeviceRGB";
        string dict = $"/Type /XObject /Subtype /Image /Width {png.Width} /Height {png.Height} " +
                       $"/ColorSpace {colorSpace} /BitsPerComponent 8{smask} /Filter /FlateDecode";

        _writer.WriteStreamObject(objNum, dict, Deflate(png.Color));
    }

    private static byte[] Deflate(byte[] data)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data, 0, data.Length);
        }

        return output.ToArray();
    }
}
