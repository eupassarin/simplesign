using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// Reads the Document Security Store (ETSI EN 319 142-1 §5.4.2, ISO 32000-2 §12.8.4.3) of a revision through the
/// object model (ADR 0032): its arrays and its <c>/VRI</c>, inline or as their own objects, each stream decoded by the
/// model's filters.
/// </summary>
internal static class DssReader
{
    private static readonly PdfName s_vri = PdfName.Of("VRI");
    private static readonly PdfName s_certs = PdfName.Of("Certs");
    private static readonly PdfName s_ocsps = PdfName.Of("OCSPs");
    private static readonly PdfName s_crls = PdfName.Of("CRLs");
    private static readonly PdfName s_cert = PdfName.Of("Cert");
    private static readonly PdfName s_ocsp = PdfName.Of("OCSP");
    private static readonly PdfName s_crl = PdfName.Of("CRL");
    private static readonly PdfName s_tu = PdfName.Of("TU");
    private static readonly PdfName s_ts = PdfName.Of("TS");

    /// <summary>The DSS's data for validation: its certificates, OCSP responses and CRLs, and those of each VRI entry.</summary>
    /// <param name="view">The revision (the latest, for validation).</param>
    /// <returns><see cref="DssValidationData.Empty"/> when there is no DSS.</returns>
    public static DssValidationData Read(PdfRevisionView view)
    {
        ArgumentNullException.ThrowIfNull(view);
        if (view.Dss is not { } dss)
        {
            return DssValidationData.Empty;
        }

        var vri = new Dictionary<string, VriData>(StringComparer.OrdinalIgnoreCase);
        if (view.Resolve(dss.Get(s_vri)) is PdfDictionary entries)
        {
            foreach (var (key, value) in entries)
            {
                if (view.Resolve(value) is PdfDictionary entry)
                {
                    vri[key.Value.ToUpperInvariant()] = new VriData(Streams(view, entry.Get(s_crl)), Streams(view, entry.Get(s_ocsp)), Streams(view, entry.Get(s_cert)))
                    {
                        Keys = [.. entry.Keys.Select(k => k.Value)],
                    };
                }
            }
        }

        return new DssValidationData(Streams(view, dss.Get(s_crls)), Streams(view, dss.Get(s_ocsps)), Streams(view, dss.Get(s_certs)), vri)
        {
            Present = true,
            Keys = [.. dss.Keys.Select(k => k.Value)],
        };
    }

    /// <summary>
    /// The DSS's object references, to merge it into the DSS an LTV update writes: its arrays (of references only), the
    /// VRI entries that are references, and its other arrays of references.
    /// </summary>
    /// <param name="view">The latest revision.</param>
    public static ExistingDssData ReadExisting(PdfRevisionView view)
    {
        ArgumentNullException.ThrowIfNull(view);
        if (view.Dss is not { } dss)
        {
            return ExistingDssData.Empty;
        }

        var vri = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (view.Resolve(dss.Get(s_vri)) is PdfDictionary entries)
        {
            foreach (var (key, value) in entries)
            {
                if (value is PdfReference reference)
                {
                    vri[key.Value.ToUpperInvariant()] = reference.Id.Number;
                }
            }
        }

        var extra = new Dictionary<string, IReadOnlyList<int>>(StringComparer.Ordinal);
        foreach (var (key, value) in dss)
        {
            if (key.Equals(s_certs) || key.Equals(s_ocsps) || key.Equals(s_crls) || key.Equals(s_vri) || key.Equals(PdfName.Type))
            {
                continue;
            }

            if (References(view, value) is { Count: > 0 } references)
            {
                extra[key.Value] = references;
            }
        }

        return new ExistingDssData(References(view, dss.Get(s_crls)), References(view, dss.Get(s_ocsps)), References(view, dss.Get(s_certs)), vri)
        {
            ExtraArrays = extra,
        };
    }

    /// <summary>The DSS as inspection reports it: how much it holds, and what is wrong with its VRI.</summary>
    /// <param name="view">The latest revision.</param>
    /// <returns>Null when there is no DSS.</returns>
    public static DssInfo? Summary(PdfRevisionView view)
    {
        ArgumentNullException.ThrowIfNull(view);
        if (view.Dss is not { } dss)
        {
            return null;
        }

        var vri = view.Resolve(dss.Get(s_vri)) as PdfDictionary;
        var validation = vri is null ? null : ValidateVri(view, vri);
        return new DssInfo
        {
            CrlCount = References(view, dss.Get(s_crls)).Count,
            OcspResponseCount = References(view, dss.Get(s_ocsps)).Count,
            CertificateCount = References(view, dss.Get(s_certs)).Count,
            HasVri = vri is not null,
            VriEntryCount = validation?.EntryCount ?? 0,
            VriHasTimestamps = validation?.AllHaveTimestamps ?? false,
            VriWarnings = validation?.Warnings ?? [],
        };
    }

    /// <summary>
    /// Checks a VRI dictionary (ISO 32000-2 §12.8.4.4): its keys are upper-case SHA-1 hashes, each entry has a time
    /// (<c>/TU</c> or <c>/TS</c>) and some validation data. The warnings are those <see cref="VriValidator"/> gives.
    /// </summary>
    internal static VriValidationResult ValidateVri(PdfRevisionView view, PdfDictionary vri)
    {
        var warnings = new List<string>();

        // The entries are the keys whose value is a dictionary: /Type /VRI, when written, is not one.
        var entries = vri.Where(e => view.Resolve(e.Value) is PdfDictionary).ToList();
        int count = entries.Count;
        if (count == 0)
        {
            warnings.Add("VRI dictionary is empty (no signature hash entries)");
            return new VriValidationResult(0, false, warnings);
        }

        int withTime = 0;
        bool anyData = false;
        foreach (var (key, value) in entries)
        {
            if (!VriValidator.IsValidVriKey(key.Value))
            {
                warnings.Add($"VRI key '{key.Value}' is not a valid uppercase hex SHA-1 hash");
            }

            if (view.Resolve(value) is PdfDictionary entry)
            {
                withTime += entry.ContainsKey(s_tu) || entry.ContainsKey(s_ts) ? 1 : 0;
                anyData |= entry.ContainsKey(s_cert) || entry.ContainsKey(s_crl) || entry.ContainsKey(s_ocsp);
            }
        }

        if (withTime < count)
        {
            warnings.Add($"VRI: {count - withTime} of {count} entries missing /TU timestamp (ISO 32000-2 §12.8.4.4)");
        }

        if (!anyData)
        {
            warnings.Add("VRI entries have no revocation data (/Cert, /CRL, or /OCSP)");
        }

        return new VriValidationResult(count, withTime == count, warnings);
    }

    /// <summary>The object numbers of an array's references (the array inline or its own object).</summary>
    private static List<int> References(PdfRevisionView view, PdfObject? array) =>
        view.Resolve(array) is PdfArray items ? [.. items.OfType<PdfReference>().Select(r => r.Id.Number)] : [];

    /// <summary>The decoded data of an array's streams; a stream that cannot be decoded is left out.</summary>
    private static List<byte[]> Streams(PdfRevisionView view, PdfObject? array)
    {
        var streams = new List<byte[]>();
        if (view.Resolve(array) is not PdfArray items)
        {
            return streams;
        }

        foreach (var item in items)
        {
            if (view.Resolve(item) is not PdfStream stream)
            {
                continue;
            }

            try
            {
                streams.Add(view.Document.DecodeStream(stream, view.Revision));
            }
            catch (Exception ex) when (ex is PdfFilterException or PdfUnsupportedFilterException)
            {
                // A stream that cannot be decoded gives no data, as before.
            }
        }

        return streams;
    }

}
