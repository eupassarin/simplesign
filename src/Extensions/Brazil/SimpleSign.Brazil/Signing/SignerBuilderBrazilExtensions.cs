using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES;

namespace SimpleSign.Brazil.Signing;

/// <summary>
/// Extension methods that add Brazil-specific AEA signing capabilities to <see cref="PadesSignerBuilder"/> and
/// to the two-phase <see cref="DeferredSignerBuilder"/>.
/// </summary>
public static class SignerBuilderBrazilExtensions
{
    /// <summary>
    /// Configures an Advanced Electronic Signature (AEA) per Lei 14.063/2020.
    /// Adds CAdES attributes (commitment-type-indication, signature-policy-identifier)
    /// and a signature manifest with signer evidence.
    /// </summary>
    /// <param name="builder">The signer builder to configure.</param>
    /// <param name="info">AEA metadata with signer name, CPF, auth method, and optional policy.</param>
    public static PadesSignerBuilder WithAdvancedSignature(this PadesSignerBuilder builder, AdvancedSignatureInfo info)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(info);
        return builder.WithMetadata(ToMetadata(info));
    }

    /// <summary>
    /// Configures an Advanced Electronic Signature (AEA) per Lei 14.063/2020 on a two-phase signature: the
    /// same attributes and manifest as <see cref="WithAdvancedSignature(PadesSignerBuilder, AdvancedSignatureInfo)"/>,
    /// fixed when the signature is prepared.
    /// </summary>
    /// <param name="builder">The deferred signer builder to configure, before <c>PrepareAsync</c>.</param>
    /// <param name="info">AEA metadata with signer name, CPF, auth method, and optional policy.</param>
    public static DeferredSignerBuilder WithAdvancedSignature(this DeferredSignerBuilder builder, AdvancedSignatureInfo info)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(info);
        return builder.WithMetadata(ToMetadata(info));
    }

    private static SignatureMetadata ToMetadata(AdvancedSignatureInfo info)
    {
        string maskedCpf = AdvancedSignatureInfo.MaskCpf(info.Cpf);

        // Build the signature manifest (tamper-proof signer evidence)
        var manifest = SignatureManifest.FromInfo(info);
        var manifestAttr = CmsAttribute.SignatureManifestAttr(manifest.ToJsonUtf8());

        // Extra CMS attributes (the policy comes from PolicyOid/PolicyUri below, once)
        var extraAttributes = new List<CmsAttribute> { manifestAttr };

        // Map to generic SignatureMetadata
        return new SignatureMetadata
        {
            SignerName = info.SignerName,
            SignerId = maskedCpf,
            SignerIdType = "CPF",
            Email = info.Email,
            IpAddress = info.IpAddress,
            AuthenticationMethod = info.AuthMethod.ToDisplayString(),
            InstitutionName = info.InstitutionName,
            InstitutionId = info.InstitutionCnpj,
            InstitutionIdType = info.InstitutionCnpj is not null ? "CNPJ" : null,
            CommitmentType = info.CommitmentType,
            LegalBasis = "Lei 14.063/2020",
            PolicyOid = info.PolicyOid,
            PolicyUri = info.PolicyUri,
            Reason = "ADVANCED ELECTRONIC SIGNATURE (Lei 14.063/2020)",
            Location = info.InstitutionName ?? string.Empty,
            ExtraAttributes = extraAttributes,
        };
    }
}
