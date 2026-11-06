namespace SimpleSign.PAdES.Signing;

/// <summary>PDF signature SubFilter value, identifying the CMS format.</summary>
public enum PdfSignatureSubFilter
{
    /// <summary>adbe.pkcs7.detached — Traditional PKCS#7 detached signature.</summary>
    AdbePkcs7Detached,
    /// <summary>ETSI.CAdES.detached — CAdES/PAdES detached signature per ETSI EN 319 122.</summary>
    EtsiCadesDetached,

    /// <summary>
    /// PBAD.PAdES with <c>/Filter /PBAD_PAdES</c> — the signature dictionary the ICP-Brasil PAdES
    /// signature policies mandate (DOC-ICP-15.03, Table A.18). The CMS is the same as
    /// ETSI.CAdES.detached.
    /// </summary>
    PbadPades,
}
