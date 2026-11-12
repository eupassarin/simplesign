using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.Brazil.Internal;

namespace SimpleSign.Brazil.IcpBrasil;

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
    /// Signs under an ICP-Brasil PAdES signature policy with the newest version that accepts the
    /// signer's root. AD-RT needs a TSA (ideally an ICP-Brasil accredited ACT). For AD-RC and AD-RA,
    /// or to choose the version, use <see cref="WithIcpBrasilPolicy(PadesSignerBuilder, IcpBrasilPolicy, IcpBrasilPadesOptions)"/>.
    /// </summary>
    /// <param name="builder">The PAdES builder.</param>
    /// <param name="policy">The policy; AD-RA also needs its artifacts, so it is refused here.</param>
    /// <param name="timestamp">The TSA, required for every policy but AD-RB.</param>
    /// <exception cref="ArgumentException">A timestamped policy without a TSA, or AD-RA.</exception>
    /// <exception cref="IcpBrasilPolicyException">No version of the policy accepts the root of the signer certificate.</exception>
    /// <example>
    /// <code>
    /// await PadesSigner.Document(pdf).WithCertificate(cert)
    ///     .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, new TimestampOptions(new Uri(actUrl)))
    ///     .SignAsync(output);
    /// </code>
    /// </example>
    public static PadesSignerBuilder WithIcpBrasilPolicy(
        this PadesSignerBuilder builder, IcpBrasilPolicy policy = IcpBrasilPolicy.AdRb, TimestampOptions? timestamp = null) =>
        builder.WithIcpBrasilPolicy(policy, new IcpBrasilPadesOptions { Timestamp = timestamp });

    /// <summary>
    /// Signs under an ICP-Brasil PAdES signature policy (DOC-ICP-15.03): writes the policy
    /// identifier with its sigPolicyHash, the <c>/Filter /PBAD_PAdES /SubFilter /PBAD.PAdES</c>
    /// signature dictionary the PAs mandate, and the level each policy needs:
    /// <list type="bullet">
    /// <item>AD-RB: B-B (B-T when a TSA is given).</item>
    /// <item>AD-RT: B-T.</item>
    /// <item>AD-RC: the signature timestamp, the DSS with VRI and a document timestamp (B-LTA).</item>
    /// <item>AD-RA: AD-RC plus the PA, LPA and LPA signature in the DSS.</item>
    /// </list>
    /// Call after <c>WithCertificate</c>/<c>WithExternalSigner</c>, so the version can be chosen
    /// by the signer's root.
    /// </summary>
    /// <param name="builder">The PAdES builder.</param>
    /// <param name="policy">The policy.</param>
    /// <param name="options">TSA, version and artifacts.</param>
    /// <exception cref="ArgumentException">A missing TSA or AD-RA artifacts, or a version or artifacts for another policy.</exception>
    /// <exception cref="IcpBrasilPolicyException">The version (chosen or given) is not in force or does not accept the signer's root.</exception>
    /// <example>
    /// <code>
    /// var tsa = new TimestampOptions(new Uri(actUrl));
    /// var version = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRa, IcpBrasilPolicyFormat.Pades, root);
    /// var artifacts = await IcpBrasilPolicyArtifacts.DownloadAsync(http, version);
    /// await PadesSigner.Document(pdf).WithCertificate(cert)
    ///     .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRa, new IcpBrasilPadesOptions { Timestamp = tsa, Artifacts = artifacts })
    ///     .SignAsync(output);
    /// </code>
    /// </example>
    public static PadesSignerBuilder WithIcpBrasilPolicy(
        this PadesSignerBuilder builder, IcpBrasilPolicy policy, IcpBrasilPadesOptions options)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(options);
        PadesPolicySetup setup = Setup(builder.SignerCertificate, builder.SignerChain, policy, options);
        builder = builder
            .WithSubFilter(PdfSignatureSubFilter.PbadPades)
            .WithSignaturePolicy(setup.Version.ToReference());
        builder = setup.Profile is null ? builder : builder.WithLevel(setup.Profile);
        return setup.DssArtifacts is null ? builder : builder.WithDssArtifacts(setup.DssArtifacts);
    }

    /// <summary>
    /// Prepares a two-phase signature under an ICP-Brasil PAdES signature policy, with the newest version that
    /// accepts the signer's root: see <see cref="WithIcpBrasilPolicy(DeferredSignerBuilder, IcpBrasilPolicy, IcpBrasilPadesOptions)"/>.
    /// </summary>
    /// <param name="builder">The deferred PAdES builder, before <c>PrepareAsync</c>.</param>
    /// <param name="policy">The policy; AD-RA also needs its artifacts, so it is refused here.</param>
    /// <param name="timestamp">The TSA, required for every policy but AD-RB.</param>
    /// <exception cref="ArgumentException">A timestamped policy without a TSA, or AD-RA.</exception>
    /// <exception cref="IcpBrasilPolicyException">No version of the policy accepts the root of the signer certificate.</exception>
    public static DeferredSignerBuilder WithIcpBrasilPolicy(
        this DeferredSignerBuilder builder, IcpBrasilPolicy policy = IcpBrasilPolicy.AdRb, TimestampOptions? timestamp = null) =>
        builder.WithIcpBrasilPolicy(policy, new IcpBrasilPadesOptions { Timestamp = timestamp });

    /// <summary>
    /// Prepares a two-phase signature under an ICP-Brasil PAdES signature policy (DOC-ICP-15.03): the same
    /// policy identifier, PBAD signature dictionary and level as
    /// <see cref="WithIcpBrasilPolicy(PadesSignerBuilder, IcpBrasilPolicy, IcpBrasilPadesOptions)"/>. The policy and
    /// the dictionary are fixed when the signature is prepared; the level and the AD-RA artifacts travel in
    /// the session and are finished when it is completed. Call after <c>WithCertificate</c>, so the version
    /// can be chosen by the signer's root, and give the TSA credentials again on the resumed builder
    /// (<c>WithTimestampOptions</c>).
    /// </summary>
    /// <param name="builder">The deferred PAdES builder, before <c>PrepareAsync</c>.</param>
    /// <param name="policy">The policy.</param>
    /// <param name="options">TSA, version and artifacts.</param>
    /// <exception cref="ArgumentException">A missing TSA or AD-RA artifacts, or a version or artifacts for another policy.</exception>
    /// <exception cref="IcpBrasilPolicyException">The version (chosen or given) is not in force or does not accept the signer's root.</exception>
    public static DeferredSignerBuilder WithIcpBrasilPolicy(
        this DeferredSignerBuilder builder, IcpBrasilPolicy policy, IcpBrasilPadesOptions options)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(options);
        PadesPolicySetup setup = Setup(builder.SignerCertificate, builder.SignerChain, policy, options);
        builder = builder
            .WithSubFilter(PdfSignatureSubFilter.PbadPades)
            .WithSignaturePolicy(setup.Version.ToReference());
        builder = setup.Profile is null ? builder : builder.WithLevel(setup.Profile);
        return setup.DssArtifacts is null ? builder : builder.WithDssArtifacts(setup.DssArtifacts);
    }

    /// <summary>What a policy asks of a PAdES signature: its version, the level and, for AD-RA, the DSS artifacts.</summary>
    private sealed record PadesPolicySetup(
        IcpBrasilSignaturePolicy Version, AdesBaselineProfile? Profile, IReadOnlyList<PdfDssArtifact>? DssArtifacts);

    private static PadesPolicySetup Setup(
        System.Security.Cryptography.X509Certificates.X509Certificate2? signer,
        IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> chain,
        IcpBrasilPolicy policy,
        IcpBrasilPadesOptions options)
    {
        if (policy is not (IcpBrasilPolicy.AdRb or IcpBrasilPolicy.AdRt or IcpBrasilPolicy.AdRc or IcpBrasilPolicy.AdRa))
        {
            throw new ArgumentException($"{policy} is not an ICP-Brasil PAdES policy.", nameof(policy));
        }

        var timestamp = options.Timestamp;
        if (policy != IcpBrasilPolicy.AdRb && timestamp is null)
        {
            throw new ArgumentException($"{PolicyName(policy)} requires a signature timestamp: pass the TSA (an ICP-Brasil ACT).", nameof(options));
        }

        if (policy == IcpBrasilPolicy.AdRa && options.Artifacts is null)
        {
            throw new ArgumentException(
                "AD-RA embeds the PA, the LPA and its signature in the DSS: pass them as Artifacts (IcpBrasilPolicyArtifacts.DownloadAsync).",
                nameof(options));
        }

        if (policy != IcpBrasilPolicy.AdRa && options.Artifacts is not null)
        {
            throw new ArgumentException("Policy artifacts are embedded only by AD-RA.", nameof(options));
        }

        var root = signer is null ? null : IcpBrasilChainValidator.FindBundledRoot(signer, chain);
        var version = ResolveVersion(policy, options.Version ?? options.Artifacts?.Policy, root);
        if (options.Artifacts is { } artifacts && artifacts.Policy.Oid != version.Oid)
        {
            throw new ArgumentException(
                $"The artifacts are for {artifacts.Policy.Oid}, but the signature uses {version.Oid}.", nameof(options));
        }

        if (timestamp is null)
        {
            return new PadesPolicySetup(version, Profile: null, DssArtifacts: null);
        }

        var ltv = options.LongTermValidation ?? new LongTermValidationOptions();
        AdesBaselineProfile profile = policy is IcpBrasilPolicy.AdRc or IcpBrasilPolicy.AdRa
            ? AdesBaselineProfile.Archive(timestamp, ltv, options.ArchiveTimestamp)
            : AdesBaselineProfile.Timestamped(timestamp);
        return new PadesPolicySetup(version, profile, options.Artifacts?.ToDssArtifacts());
    }

    /// <summary>
    /// The version of <paramref name="policy"/> <see cref="WithIcpBrasilPolicy(PadesSignerBuilder, IcpBrasilPolicy, IcpBrasilPadesOptions)"/>
    /// would pick for this builder's signer: the newest in-force PAdES version that accepts the
    /// signer's root. Use it to download the AD-RA artifacts of the right version.
    /// </summary>
    /// <param name="builder">The PAdES builder, with the signer set.</param>
    /// <param name="policy">The policy.</param>
    /// <exception cref="IcpBrasilPolicyException">No version accepts the signer's root.</exception>
    public static IcpBrasilSignaturePolicy ResolveIcpBrasilPolicy(this PadesSignerBuilder builder, IcpBrasilPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var root = builder.SignerCertificate is { } signer
            ? IcpBrasilChainValidator.FindBundledRoot(signer, builder.SignerChain)
            : null;
        return ResolveVersion(policy, requested: null, root);
    }

    /// <summary>
    /// The version of <paramref name="policy"/> <see cref="WithIcpBrasilPolicy(DeferredSignerBuilder, IcpBrasilPolicy, IcpBrasilPadesOptions)"/>
    /// would pick for this builder's signer: the newest in-force PAdES version that accepts the
    /// signer's root. Use it to download the AD-RA artifacts of the right version.
    /// </summary>
    /// <param name="builder">The deferred PAdES builder, with the signer set.</param>
    /// <param name="policy">The policy.</param>
    /// <exception cref="IcpBrasilPolicyException">No version accepts the signer's root.</exception>
    public static IcpBrasilSignaturePolicy ResolveIcpBrasilPolicy(this DeferredSignerBuilder builder, IcpBrasilPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var root = builder.SignerCertificate is { } signer
            ? IcpBrasilChainValidator.FindBundledRoot(signer, builder.SignerChain)
            : null;
        return ResolveVersion(policy, requested: null, root);
    }

    private static IcpBrasilSignaturePolicy ResolveVersion(IcpBrasilPolicy policy, IcpBrasilSignaturePolicy? requested, System.Security.Cryptography.X509Certificates.X509Certificate2? root)
    {
        if (requested is null)
        {
            // Older PAs list only the roots that existed when they were issued: pick the newest
            // version that accepts the signer's root.
            return root is null
                ? IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Pades)
                : IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Pades, root);
        }

        if (requested.Info.Policy != policy || requested.Info.Format != IcpBrasilPolicyFormat.Pades)
        {
            throw new ArgumentException($"{requested.Oid} is not a PAdES {PolicyName(policy)} policy.", nameof(requested));
        }

        var now = DateTimeOffset.UtcNow;
        if (!requested.IsValidAt(now))
        {
            throw new IcpBrasilPolicyException(requested.RevokedAt is { } revoked && revoked <= now
                ? $"The policy {requested.Oid} was revoked on {revoked:yyyy-MM-dd}."
                : $"The policy {requested.Oid} may be used from {requested.NotBefore:yyyy-MM-dd} to {requested.NotAfter:yyyy-MM-dd}.");
        }

        if (root is not null && IcpBrasilSignaturePolicies.TryGetRules(requested.Oid, out var rules) && !rules.AcceptsRoot(root))
        {
            throw new IcpBrasilPolicyException($"The policy {requested.Oid} does not accept the signer's root ({root.Subject}).");
        }

        return requested;
    }

    private static string PolicyName(IcpBrasilPolicy policy) => policy switch
    {
        IcpBrasilPolicy.AdRb => "AD-RB",
        IcpBrasilPolicy.AdRt => "AD-RT",
        IcpBrasilPolicy.AdRc => "AD-RC",
        IcpBrasilPolicy.AdRa => "AD-RA",
        _ => policy.ToString(),
    };

    /// <summary>
    /// Marks the PDF as a health document for VALIDAR: writes the document-type OID
    /// (2.16.76.1.12.1.{n}) and, for each professional, the council registration OIDs
    /// (2.16.76.1.4.2.{council}.1 number, .2 UF, .3 specialty) as entries of the document
    /// information dictionary, in the signing revision.
    /// </summary>
    /// <remarks>
    /// The VALIDAR guide requires these items "como metadados" but does not say where; this writes
    /// them to the document information dictionary, keyed by OID. Check the result on
    /// validar.iti.gov.br with your certificate. Combine with <see cref="WithIcpBrasilPolicy(PadesSignerBuilder, IcpBrasilPolicy, IcpBrasilPadesOptions)"/>.
    /// </remarks>
    /// <param name="builder">The PAdES builder.</param>
    /// <param name="type">The document type.</param>
    /// <param name="professionals">The registration of the prescriber (CFM, CFO…) and, when relevant, the pharmacist (CFF).</param>
    /// <exception cref="ArgumentException">No professional was given.</exception>
    public static PadesSignerBuilder WithHealthDocument(
        this PadesSignerBuilder builder, HealthDocumentType type, params ProfessionalRegistration[] professionals)
    {
        ArgumentNullException.ThrowIfNull(builder);
        foreach (var (key, value) in HealthDocumentEntries(type, professionals))
        {
            builder = builder.WithDocumentInfo(key, value);
        }

        return builder;
    }

    /// <summary>
    /// Marks the PDF of a two-phase signature as a health document for VALIDAR: the same entries as
    /// <see cref="WithHealthDocument(PadesSignerBuilder, HealthDocumentType, ProfessionalRegistration[])"/>, written
    /// in the signing revision when the signature is prepared.
    /// </summary>
    /// <param name="builder">The deferred PAdES builder, before <c>PrepareAsync</c>.</param>
    /// <param name="type">The document type.</param>
    /// <param name="professionals">The registration of the prescriber (CFM, CFO…) and, when relevant, the pharmacist (CFF).</param>
    /// <exception cref="ArgumentException">No professional was given.</exception>
    public static DeferredSignerBuilder WithHealthDocument(
        this DeferredSignerBuilder builder, HealthDocumentType type, params ProfessionalRegistration[] professionals)
    {
        ArgumentNullException.ThrowIfNull(builder);
        foreach (var (key, value) in HealthDocumentEntries(type, professionals))
        {
            builder = builder.WithDocumentInfo(key, value);
        }

        return builder;
    }

    /// <summary>The document information entries of a health document: its type and each professional's registration, keyed by OID.</summary>
    private static List<(string Key, string Value)> HealthDocumentEntries(HealthDocumentType type, ProfessionalRegistration[] professionals)
    {
        ArgumentNullException.ThrowIfNull(professionals);
        if (professionals.Length == 0)
        {
            throw new ArgumentException("At least one professional registration is required.", nameof(professionals));
        }

        var entries = new List<(string Key, string Value)> { ($"{BrazilOids.HealthDocumentArc}{(int)type}", DocumentTypeName(type)) };
        foreach (var registration in professionals)
        {
            ArgumentNullException.ThrowIfNull(registration);
            string arc = $"{BrazilOids.ProfessionalCouncilArc}{(int)registration.Council}.";
            entries.Add((arc + "1", registration.RegistrationNumber));
            if (registration.StateCode is not null)
            {
                entries.Add((arc + "2", registration.StateCode));
            }

            if (registration.Specialty is not null)
            {
                entries.Add((arc + "3", registration.Specialty));
            }
        }

        return entries;
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
