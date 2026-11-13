namespace SimpleSign.Core.Validation;

/// <summary>Options for the validation engine.</summary>
public sealed class ValidationOptions
{
    /// <summary>Checks revocation (CRL/OCSP). Requires network access. Default: true.</summary>
    public bool CheckRevocation { get; init; } = true;

    /// <summary>Includes system root certificates as trust anchors. Default: true.</summary>
    public bool TrustSystemRoots { get; init; } = true;

    /// <summary>Additional root certificates for trust (e.g., ICP-Brasil chain).</summary>
    public IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>? TrustedRoots { get; init; }

    /// <summary>Timeout for AIA downloads, revocation checks (CRL/OCSP), and certificate-chain URL retrieval. Default: 10 seconds.</summary>
    public TimeSpan NetworkTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The validation policy: accepted algorithms and key sizes, constraints on the signing certificate.
    /// Default: <see cref="Policies.ValidationPolicy.Default"/> (the policy embedded in SimpleSign). Load one with <see cref="Policies.ValidationPolicy.Load"/>.
    /// </summary>
    public Policies.ValidationPolicy Policy { get; init; } = Policies.ValidationPolicy.Default;

    /// <summary>
    /// Chooses the validation policy for each signature by the signature policy it names; when set, it replaces
    /// <see cref="Policy"/>. Null: <see cref="Policy"/> for every signature.
    /// </summary>
    public Policies.IPolicyProvider? PolicyProvider { get; init; }

    /// <summary>The policy for a signature that names <paramref name="signaturePolicyOid"/> (or none).</summary>
    internal Policies.ValidationPolicy PolicyFor(string? signaturePolicyOid) =>
        PolicyProvider?.ValidationFor(signaturePolicyOid) ?? Policy;

    /// <summary>
    /// Finds the document of the signature policy a signature names when the signature does not carry it. Null: a policy
    /// document is available only from the signature's signature-policy-store.
    /// </summary>
    public Policies.ISignaturePolicyDocumentProvider? SignaturePolicyDocuments { get; init; }

    /// <summary>Whether <see cref="SignaturePolicyDocuments"/> has the document of <paramref name="signaturePolicyOid"/>: true, or null when unknown.</summary>
    internal bool? PolicyDocumentFound(string? signaturePolicyOid) =>
        signaturePolicyOid is not null && SignaturePolicyDocuments?.Find(signaturePolicyOid) is not null ? true : null;

    /// <summary>How validation data is fetched: revocation strategy and fallback, AIA, untrusted chains. Default: <see cref="VerifierOptions.Default"/>.</summary>
    public VerifierOptions Verifier { get; init; } = VerifierOptions.Default;

    /// <summary>How much of each signature is validated. Default: <see cref="ValidationLevel.ArchivalData"/>.</summary>
    public ValidationLevel Level { get; init; } = ValidationLevel.ArchivalData;

    /// <summary>
    /// The trusted lists the trust anchors come from, for the <c>TrustedLists</c> constraints of the validators (the
    /// PAdES validator also reads those of its trust anchor providers, such as a country extension's). Null when the
    /// anchors are not from trusted lists.
    /// </summary>
    public IReadOnlyList<Extensions.TrustedListInfo>? TrustedLists { get; init; }

    /// <summary>
    /// Trust anchors that depend on time, such as trusted lists with a service history (ETSI TS 119 612 §5.6, TS 119 615).
    /// When a certificate does not reach today's anchors, the validators try again with the anchors of these providers at
    /// the time that matters: the signature time-stamp's genTime for its TSA, the proof of existence of the signature for
    /// the signer. A service withdrawn after the signature was proven to exist then still vouches for it. Null or empty:
    /// only today's anchors count.
    /// </summary>
    public IReadOnlyList<Extensions.ITimedTrustAnchorProvider>? TimedTrustAnchors { get; init; }

    /// <summary>
    /// A trust profile (<c>IofeProfile</c>, <c>IcpBrasilProfile</c>, <c>GovBrProfile</c>): its anchors, trusted lists and
    /// chain validation are added to the validator's, and its validation policy applies while <see cref="Policy"/> is
    /// left at its default. Null: none.
    /// </summary>
    public Extensions.TrustProfile? Profile { get; init; }

    /// <summary>
    /// The qualifiers that give each validated signature its qualification under a legal framework
    /// (<see cref="SignatureValidationResult.Qualification"/>); a <see cref="Profile"/>'s are added. Null or empty: none.
    /// </summary>
    public IReadOnlyList<Extensions.ISignatureQualifier>? SignatureQualifiers { get; init; }

    /// <summary>The qualification of a validated signature: the first qualifier that gives one; null when none does.</summary>
    internal SignatureQualification? Qualify(Extensions.SignatureQualificationContext context) =>
        SignatureQualifiers is { Count: > 0 } qualifiers ? qualifiers.Select(q => q.Qualify(context)).FirstOrDefault(q => q is not null) : null;

    /// <summary>These options with the qualifiers of <paramref name="extensions"/> added (the country-extension constructors).</summary>
    internal ValidationOptions WithQualifiersFrom(IEnumerable<Extensions.ICountryExtension>? extensions)
    {
        // An extension written before SignatureQualifiers (or a mock) may give null.
        var added = extensions?.SelectMany(e => e.SignatureQualifiers ?? []).ToList() ?? [];
        return added.Count == 0 ? this : Copy([.. SignatureQualifiers ?? [], .. added]);
    }

    /// <summary>
    /// These options with <see cref="Profile"/> applied: its policy (when <see cref="Policy"/> is the default), its roots
    /// in <see cref="TrustedRoots"/>, its trusted lists and its timed anchors. The same instance without a profile.
    /// </summary>
    internal ValidationOptions WithProfileApplied()
    {
        if (Profile is not { } profile)
        {
            return this;
        }

        var anchors = profile.Anchors();
        IReadOnlyList<Extensions.ISignatureQualifier> qualifiers = [.. SignatureQualifiers ?? [], .. profile.SignatureQualifiers];
        var lists = profile.TrustAnchorProviders.OfType<Extensions.ITrustedListInfoProvider>().SelectMany(p => p.TrustedLists).ToList();
        var timed = profile.TrustAnchorProviders.OfType<Extensions.ITimedTrustAnchorProvider>().ToList();
        return new ValidationOptions
        {
            CheckRevocation = CheckRevocation,
            TrustSystemRoots = TrustSystemRoots,
            TrustedRoots = anchors.Count == 0 ? TrustedRoots : [.. TrustedRoots ?? [], .. anchors],
            NetworkTimeout = NetworkTimeout,
            Policy = ReferenceEquals(Policy, Policies.ValidationPolicy.Default) ? profile.ValidationPolicy : Policy,
            PolicyProvider = PolicyProvider,
            SignaturePolicyDocuments = SignaturePolicyDocuments,
            Verifier = Verifier,
            Level = Level,
            TrustedLists = lists.Count == 0 ? TrustedLists : [.. TrustedLists ?? [], .. lists],
            TimedTrustAnchors = timed.Count == 0 ? TimedTrustAnchors : [.. TimedTrustAnchors ?? [], .. timed],
            Profile = profile,
            SignatureQualifiers = qualifiers,
        };
    }

    private ValidationOptions Copy(IReadOnlyList<Extensions.ISignatureQualifier> qualifiers) => new()
    {
        CheckRevocation = CheckRevocation,
        TrustSystemRoots = TrustSystemRoots,
        TrustedRoots = TrustedRoots,
        NetworkTimeout = NetworkTimeout,
        Policy = Policy,
        PolicyProvider = PolicyProvider,
        SignaturePolicyDocuments = SignaturePolicyDocuments,
        Verifier = Verifier,
        Level = Level,
        TrustedLists = TrustedLists,
        TimedTrustAnchors = TimedTrustAnchors,
        Profile = Profile,
        SignatureQualifiers = qualifiers,
    };

    /// <summary>Whether signature timestamps are validated (and give a proof of existence).</summary>
    internal bool ValidatesTimestamps => Level >= ValidationLevel.Timestamps;

    /// <summary>Whether revocation is checked: <see cref="CheckRevocation"/> and a level that includes long-term data.</summary>
    internal bool ChecksRevocation => CheckRevocation && Level >= ValidationLevel.LongTermData;

    /// <summary>Whether revocation is checked for a chain that is or is not trusted.</summary>
    internal bool ChecksRevocationFor(bool chainTrusted) => ChecksRevocation && (chainTrusted || Verifier.CheckRevocationForUntrustedChains);

    /// <summary>Whether long-term validation data is validated.</summary>
    internal bool ValidatesLongTermData => Level >= ValidationLevel.LongTermData;

    /// <summary>Whether archive timestamps are validated.</summary>
    internal bool ValidatesArchivalData => Level >= ValidationLevel.ArchivalData;

    /// <summary>Default instance with all options at their default values.</summary>
    public static ValidationOptions Default { get; } = new();
}
