using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Envelope;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>
/// The ICP-Brasil levels a field of a signature envelope can ask for (ADR 0033): a PAdES signature of ICP-Brasil
/// (SubFilter <c>PBAD.PAdES</c>) under an AD-RB or AD-RT signature policy of DOC-ICP-15.03, any version of it. Each
/// describes itself in the manifest, so checking it needs no ICP-Brasil package; signing is configured as always
/// (<see cref="IcpBrasilSigningExtensions.WithIcpBrasilPolicy(PAdES.PadesSignerBuilder, IcpBrasilPolicy, TimestampOptions?)"/>).
/// </summary>
/// <example>
/// <code>
/// var signer = new EnvelopeSigner { Name = "Maria", Level = IcpBrasilEnvelopeLevels.AdRt, … };
/// // and, to sign the field:
/// await PadesSigner.Document(pdf).WithCertificate(cert).WithProfile(IcpBrasilProfile.Create())
///     .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, new TimestampOptions(new Uri(actUrl)))
///     .WithEnvelopeField("SimpleSign_1").SignAsync();
/// </code>
/// </example>
public static class IcpBrasilEnvelopeLevels
{
    /// <summary>AD-RB in PAdES: <c>PBAD.PAdES</c>, the PAdES AD-RB policy (2.16.76.1.7.1.11.1 and its versions).</summary>
    public static EnvelopeLevel AdRb { get; } = new()
    {
        Id = "icp-ad-rb",
        SubFilters = ["PBAD.PAdES"],
        PolicyOids = ["2.16.76.1.7.1.11.1", "2.16.76.1.7.1.11.1.1", "2.16.76.1.7.1.11.1.2", "2.16.76.1.7.1.11.1.3"],
    };

    /// <summary>AD-RT in PAdES: <c>PBAD.PAdES</c>, the PAdES AD-RT policy (2.16.76.1.7.1.12.1 and its versions), and a signature time-stamp.</summary>
    public static EnvelopeLevel AdRt { get; } = new()
    {
        Id = "icp-ad-rt",
        Baseline = AdesBaselineLevel.Timestamped,
        Timestamp = true,
        SubFilters = ["PBAD.PAdES"],
        PolicyOids = ["2.16.76.1.7.1.12.1", "2.16.76.1.7.1.12.1.1", "2.16.76.1.7.1.12.1.2", "2.16.76.1.7.1.12.1.3"],
    };

    /// <summary>The level of an id: <c>icp-ad-rb</c> or <c>icp-ad-rt</c>; null for another.</summary>
    /// <param name="id">The id.</param>
    public static EnvelopeLevel? FromId(string id) => id switch
    {
        "icp-ad-rb" => AdRb,
        "icp-ad-rt" => AdRt,
        _ => null,
    };
}
