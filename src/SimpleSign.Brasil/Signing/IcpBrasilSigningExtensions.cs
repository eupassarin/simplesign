using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.Brasil.Signing;

/// <summary>Health document types with an ITI OID (2.16.76.1.12.1.{n}), as listed in the VALIDAR developer guide.</summary>
public enum HealthDocumentType
{
    /// <summary>Prescrição de medicamento (2.16.76.1.12.1.1).</summary>
    Prescricao = 1,

    /// <summary>Atestado médico (2.16.76.1.12.1.2).</summary>
    Atestado = 2,

    /// <summary>Solicitação de exame (2.16.76.1.12.1.3).</summary>
    SolicitacaoExame = 3,

    /// <summary>Relatório médico (2.16.76.1.12.1.11).</summary>
    Relatorio = 11,
}

/// <summary>Signs PDFs as the ITI expects for ICP-Brasil signatures and VALIDAR.</summary>
public static class IcpBrasilSigningExtensions
{
    /// <summary>
    /// Signs under an ICP-Brasil PAdES signature policy: writes the current version of the policy
    /// (e.g. PAdES AD-RB v1.3) with its sigPolicyHash, and uses the ETSI.CAdES.detached sub-filter.
    /// AD-RT also needs a TSA — ideally an ICP-Brasil accredited ACT — and sets the B-T level.
    /// The VALIDAR portal expects AD-RB or AD-RT.
    /// </summary>
    /// <param name="builder">The PAdES builder.</param>
    /// <param name="policy"><see cref="IcpBrasilPolicy.AdRb"/> or <see cref="IcpBrasilPolicy.AdRt"/>.</param>
    /// <param name="timestamp">The TSA, required for AD-RT.</param>
    /// <exception cref="ArgumentException">AD-RT without a TSA, or a policy other than AD-RB/AD-RT.</exception>
    /// <example>
    /// <code>
    /// await PadesSigner.Document(pdf).WithCertificate(cert)
    ///     .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, new TimestampOptions(new Uri(actUrl)))
    ///     .SignAsync(output);
    /// </code>
    /// </example>
    public static PadesSignerBuilder WithIcpBrasilPolicy(
        this PadesSignerBuilder builder, IcpBrasilPolicy policy = IcpBrasilPolicy.AdRb, TimestampOptions? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (policy is not (IcpBrasilPolicy.AdRb or IcpBrasilPolicy.AdRt))
        {
            throw new ArgumentException("Only AD-RB and AD-RT are supported for PAdES signing.", nameof(policy));
        }

        if (policy == IcpBrasilPolicy.AdRt && timestamp is null)
        {
            throw new ArgumentException("AD-RT requires a signature timestamp: pass the TSA (an ICP-Brasil ACT).", nameof(timestamp));
        }

        var current = IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Pades);
        builder = builder
            .WithSubFilter(PdfSignatureSubFilter.EtsiCadesDetached)
            .WithSignaturePolicy(current.ToReference());
        return timestamp is null ? builder : builder.WithLevel(AdesBaselineProfile.Timestamped(timestamp));
    }

    /// <summary>
    /// Marks the PDF as a health document for VALIDAR: writes the document-type OID
    /// (2.16.76.1.12.1.{n}) and, for each professional, the council registration OIDs
    /// (2.16.76.1.4.2.{council}.1 number, .2 UF, .3 specialty) as entries of the document
    /// information dictionary, in the signing revision.
    /// </summary>
    /// <remarks>
    /// The VALIDAR guide requires these items "como metadados" but does not say where; this writes
    /// them to the document information dictionary, keyed by OID. Check the result on
    /// validar.iti.gov.br with your certificate. Combine with <see cref="WithIcpBrasilPolicy"/>.
    /// </remarks>
    /// <param name="builder">The PAdES builder.</param>
    /// <param name="type">The document type.</param>
    /// <param name="professionals">The registration of the prescriber (CFM, CFO…) and, when relevant, the pharmacist (CFF).</param>
    /// <exception cref="ArgumentException">No professional was given.</exception>
    public static PadesSignerBuilder WithHealthDocument(
        this PadesSignerBuilder builder, HealthDocumentType type, params ProfessionalRegistration[] professionals)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(professionals);
        if (professionals.Length == 0)
        {
            throw new ArgumentException("At least one professional registration is required.", nameof(professionals));
        }

        builder = builder.WithDocumentInfo($"{Constants.BrasilOids.HealthDocumentArc}{(int)type}", DocumentTypeName(type));
        foreach (var registration in professionals)
        {
            ArgumentNullException.ThrowIfNull(registration);
            string arc = $"{Constants.BrasilOids.ProfessionalCouncilArc}{(int)registration.Council}.";
            builder = builder.WithDocumentInfo(arc + "1", registration.RegistrationNumber);
            if (registration.StateCode is not null)
            {
                builder = builder.WithDocumentInfo(arc + "2", registration.StateCode);
            }

            if (registration.Specialty is not null)
            {
                builder = builder.WithDocumentInfo(arc + "3", registration.Specialty);
            }
        }

        return builder;
    }

    /// <summary>The policy as a signature-policy-identifier reference (OID, sigPolicyHash, URI).</summary>
    /// <param name="policy">The ICP-Brasil policy.</param>
    public static SignaturePolicyReference ToReference(this IcpBrasilSignaturePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return new SignaturePolicyReference(policy.Oid, policy.HashAlgorithmOid, policy.PolicyHash, policy.Uri);
    }

    private static string DocumentTypeName(HealthDocumentType type) => type switch
    {
        HealthDocumentType.Prescricao => "Prescrição de medicamento",
        HealthDocumentType.Atestado => "Atestado médico",
        HealthDocumentType.SolicitacaoExame => "Solicitação de exame",
        HealthDocumentType.Relatorio => "Relatório médico",
        _ => type.ToString(),
    };
}
