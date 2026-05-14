using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES;

namespace SimpleSign.Brasil.Signing;

/// <summary>
/// Extension methods that add Brazil-specific AEA signing capabilities to <see cref="SignerBuilder"/>.
/// </summary>
public static class SignerBuilderBrasilExtensions
{
    /// <summary>
    /// Configures an Advanced Electronic Signature (AEA) per Lei 14.063/2020.
    /// Adds CAdES attributes (commitment-type-indication, signature-policy-identifier)
    /// and a signature manifest with signer evidence.
    /// </summary>
    /// <param name="builder">The signer builder to configure.</param>
    /// <param name="info">AEA metadata with signer name, CPF, auth method, and optional policy.</param>
    public static SignerBuilder WithAdvancedSignature(this SignerBuilder builder, AdvancedSignatureInfo info)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(info);

        string maskedCpf = AdvancedSignatureInfo.MaskCpf(info.Cpf);

        // Build the signature manifest (tamper-proof signer evidence)
        var manifest = SignatureManifest.FromInfo(info);
        var manifestAttr = CmsAttribute.SignatureManifestAttr(manifest.ToJsonUtf8());

        // Build extra CMS attributes list
        var extraAttributes = new List<CmsAttribute> { manifestAttr };
        if (info.PolicyOid is not null)
        {
            extraAttributes.Add(CmsAttribute.SignaturePolicyIdentifier(info.PolicyOid, info.PolicyUri));
        }

        // Map to generic SignatureMetadata
        var metadata = new SignatureMetadata
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

        return builder.WithMetadata(metadata);
    }
}
