namespace SimpleSign.DocxToPdf;

/// <summary>Static entry points for DOCX-to-PDF conversion.</summary>
public static class DocxToPdfConverter
{
    /// <summary>Creates a converter builder from a file path.</summary>
    /// <param name="path">The path to the DOCX file.</param>
    /// <returns>A builder for configuring and executing the conversion.</returns>
    public static DocxToPdfBuilder FromFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException("DOCX file not found.", path);
        }

        byte[] data = File.ReadAllBytes(path);
        return new DocxToPdfBuilder(data);
    }

    /// <summary>Creates a converter builder from a stream.</summary>
    /// <param name="docxStream">The DOCX stream.</param>
    /// <returns>A builder for configuring and executing the conversion.</returns>
    public static DocxToPdfBuilder FromStream(Stream docxStream)
    {
        ArgumentNullException.ThrowIfNull(docxStream);

        using var ms = new MemoryStream();
        docxStream.CopyTo(ms);
        return new DocxToPdfBuilder(ms.ToArray());
    }

    /// <summary>Creates a converter builder from a byte array.</summary>
    /// <param name="docxBytes">The DOCX file bytes.</param>
    /// <returns>A builder for configuring and executing the conversion.</returns>
    public static DocxToPdfBuilder FromBytes(byte[] docxBytes)
    {
        ArgumentNullException.ThrowIfNull(docxBytes);
        return new DocxToPdfBuilder(docxBytes);
    }
}
