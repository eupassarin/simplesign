using System.Diagnostics.CodeAnalysis;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.Fiscal;

/// <summary>
/// Signs Brazilian fiscal XML (NF-e, NFC-e, CT-e, MDF-e, events, NFS-e, eSocial, EFD-Reinf) with the enveloped XML-DSig
/// signature its layout requires, under ICP-Brasil: the builder comes configured with the layout (signed element, hash,
/// placement, C14N), the ICP-Brasil anchors and the layout's signing policy (<see cref="FiscalDocumentProfile.SigningPolicy"/>).
/// Add the certificate and sign. The XML is not reformatted: send exactly the bytes returned, since any change after
/// signing breaks the signature (SEFAZ rejection 297/298).
/// </summary>
/// <example>
/// <code>
/// byte[] signed = await FiscalXmlSigner.Document(nfe, FiscalDocumentProfile.NFe).WithCertificate(eCnpj).SignAsync();
/// byte[] batch = await FiscalXmlSigner.Document(enviNFe, FiscalDocumentProfile.NFe).WithCertificate(eCnpj).SignAllAsync();
/// // A3 token: .WithExternalSigner(certificate, pkcs11Signer); two phases: FiscalXmlSigner.Deferred(…)
/// </code>
/// </example>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public static class FiscalXmlSigner
{
    /// <summary>A one-call builder for <paramref name="xml"/>, configured for <paramref name="layout"/> under ICP-Brasil.</summary>
    /// <param name="xml">The fiscal XML (UTF-8).</param>
    /// <param name="layout">The layout, e.g. <see cref="FiscalDocumentProfile.NFe"/>.</param>
    /// <param name="options">The ICP-Brasil options (HTTP client for the revocation check, extra roots).</param>
    /// <returns>The builder; set the certificate and call <c>SignAsync</c> or <c>SignAllAsync</c>.</returns>
    /// <exception cref="ArgumentException">The XML is an eSocial or EFD-Reinf batch (<c>envioLoteEventos</c>): sign each event before building the batch.</exception>
    public static XmlDsigSignerBuilder Document(byte[] xml, FiscalDocumentProfile layout, IcpBrasilExtensionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(xml);
        ArgumentNullException.ThrowIfNull(layout);
        return layout.Apply(XmlDsigSigner.Document(xml))
            .WithProfile(IcpBrasilProfile.Create(options))
            .WithSigningPolicy(layout.SigningPolicy);
    }

    /// <summary>
    /// A two-phase builder for <paramref name="xml"/>: the server prepares with the public certificate, the key signs
    /// the SignedInfo elsewhere (an A3 token behind the SimpleSign Agent), and the server completes it.
    /// </summary>
    /// <param name="xml">The fiscal XML (UTF-8).</param>
    /// <param name="layout">The layout.</param>
    /// <param name="options">The ICP-Brasil options.</param>
    /// <returns>The builder; set the certificate and the session key and call <c>PrepareAsync</c>.</returns>
    /// <exception cref="ArgumentException">The XML is an eSocial or EFD-Reinf batch (<c>envioLoteEventos</c>).</exception>
    public static XmlDsigDeferredSignerBuilder Deferred(byte[] xml, FiscalDocumentProfile layout, IcpBrasilExtensionOptions? options = null) =>
        XmlDsigDeferredSigner.From(Document(xml, layout, options));
}
