using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>Runs alone: RefreshAsync changes the process-wide policy catalog.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PolicyCatalogCollection
{
    /// <summary>Collection name.</summary>
    public const string Name = "ICP-Brasil policy catalog";
}

/// <summary>Downloading and verifying the ITI LPA (<see cref="IcpBrasilSignaturePolicies.RefreshAsync(HttpClient, IcpBrasilPolicyFormat, CancellationToken)"/>).</summary>
[Trait("Category", "Unit")]
[Collection(PolicyCatalogCollection.Name)]
public sealed class IcpBrasilLpaRefreshTests
{
    private const string KnownOid = "2.16.76.1.7.1.11.1.3";
    private const string NewOid = "2.16.76.1.7.1.11.1.9";
    private const string NewPaUri = "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_9.der";
    private static readonly (string, string) ItiCnpj = ("2.16.76.1.3.3", "04039532000193");
    private static readonly DateTimeOffset Revoked = new(2036, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Parse_ReadsEntriesAndNextUpdate()
    {
        byte[] pa = PolicyDocument(NewOid);
        var lpa = IcpBrasilLpa.Parse(Lpa(pa));

        lpa.NextUpdate.Year.ShouldBe(2027);
        lpa.Entries.Count.ShouldBe(2);
        lpa.Entries[0].Oid.ShouldBe(KnownOid);
        lpa.Entries[0].RevokedAt.ShouldBe(Revoked);
        lpa.Entries[1].Digest.ToArray().ShouldBe(SHA256.HashData(pa));
    }

    [Fact]
    public void Parse_Garbage_Throws() => Should.Throw<ArgumentException>(() => IcpBrasilLpa.Parse([0x30, 0x00]));

    [Fact]
    public async Task RefreshAsync_SignedByIti_UpdatesKnownAndAddsNewPolicies()
    {
        using var pki = TestPki.Create(leafExpired: false, subjectAltNames: ItiCnpj);
        byte[] pa = PolicyDocument(NewOid);
        byte[] lpa = Lpa(pa);
        try
        {
            await IcpBrasilSignaturePolicies.RefreshAsync(Http(lpa, Sign(pki, lpa), pa), IcpBrasilPolicyFormat.Pades, Validator(pki), CancellationToken.None);

            IcpBrasilSignaturePolicies.TryFind(KnownOid, out var known).ShouldBeTrue();
            known.RevokedAt.ShouldBe(Revoked);
            known.PolicyHashHex.ShouldBe("23E4BE4B9B362172E4EBB0E72B86A133ECE5AAD843D8651C6E38A0BA3F08FC60", "the hash of a known PA is kept");
            IcpBrasilSignaturePolicies.TryFind(NewOid, out var added).ShouldBeTrue();
            added.PolicyHashHex.ShouldBe(new string('A', 64));
            added.Uri.ShouldBe(NewPaUri);
            IcpBrasilSignaturePolicies.All.Count.ShouldBe(101);
        }
        finally
        {
            IcpBrasilSignaturePolicies.ResetToEmbedded();
        }
    }

    [Fact]
    public async Task RefreshAsync_NotSignedByIti_ThrowsAndKeepsCatalog()
    {
        using var pki = TestPki.Create(leafExpired: false, subjectAltNames: ("2.16.76.1.3.3", "11222333000181"));
        byte[] pa = PolicyDocument(NewOid);
        byte[] lpa = Lpa(pa);

        await Should.ThrowAsync<CryptographicException>(() =>
            IcpBrasilSignaturePolicies.RefreshAsync(Http(lpa, Sign(pki, lpa), pa), IcpBrasilPolicyFormat.Pades, Validator(pki), CancellationToken.None));
        IcpBrasilSignaturePolicies.TryFind(NewOid, out _).ShouldBeFalse();
    }

    [Fact]
    public async Task RefreshAsync_TamperedLpa_Throws()
    {
        using var pki = TestPki.Create(leafExpired: false, subjectAltNames: ItiCnpj);
        byte[] pa = PolicyDocument(NewOid);
        byte[] lpa = Lpa(pa);
        byte[] signature = Sign(pki, lpa);
        byte[] tampered = Lpa(PolicyDocument("2.16.76.1.7.1.11.1.8"));

        await Should.ThrowAsync<CryptographicException>(() =>
            IcpBrasilSignaturePolicies.RefreshAsync(Http(tampered, signature, pa), IcpBrasilPolicyFormat.Pades, Validator(pki), CancellationToken.None));
    }

    [Fact]
    public async Task RefreshAsync_PaNotMatchingLpaDigest_ThrowsAndKeepsCatalog()
    {
        using var pki = TestPki.Create(leafExpired: false, subjectAltNames: ItiCnpj);
        byte[] lpa = Lpa(PolicyDocument(NewOid));
        byte[] otherPa = PolicyDocument(NewOid, hashByte: 0xBB);

        await Should.ThrowAsync<CryptographicException>(() =>
            IcpBrasilSignaturePolicies.RefreshAsync(Http(lpa, Sign(pki, lpa), otherPa), IcpBrasilPolicyFormat.Pades, Validator(pki), CancellationToken.None));
        IcpBrasilSignaturePolicies.TryFind(KnownOid, out var known).ShouldBeTrue();
        known.RevokedAt.ShouldBeNull();
    }

    private static IcpBrasilChainValidator Validator(TestPki pki) =>
        new(new HttpClient(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)))))
        {
            TrustAnchorsOverride = [pki.Root],
        };

    private static HttpClient Http(byte[] lpa, byte[] signature, byte[] pa) =>
        new(new MockHttpHandler(request =>
        {
            byte[]? body = request.RequestUri!.AbsolutePath switch
            {
                "/LPA_PAdES.der" => lpa,
                "/LPA_PAdES.p7s" => signature,
                "/PA_PAdES_AD_RB_v1_9.der" when request.RequestUri.Scheme == "https" => pa,
                _ => null,
            };
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }));

    private static byte[] Sign(TestPki pki, byte[] content) =>
        CmsSignatureBuilder.Build(content, pki.Leaf, HashAlgorithmName.SHA256, DateTimeOffset.UtcNow, [pki.Ac], padesAttributes: false);

    /// <summary>An LPA with the known PAdES AD-RB v1.3 (now revoked in 2036) and a new v1.9.</summary>
    private static byte[] Lpa(byte[] newPa)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                Entry(w, KnownOid, "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_3.der", new byte[32], Revoked);
                Entry(w, NewOid, NewPaUri, SHA256.HashData(newPa), null);
            }

            w.WriteGeneralizedTime(new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));
        }

        return w.Encode();
    }

    private static void Entry(AsnWriter w, string oid, string uri, byte[] digest, DateTimeOffset? revoked)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteGeneralizedTime(new DateTimeOffset(2025, 7, 23, 0, 0, 0, TimeSpan.Zero));
                w.WriteGeneralizedTime(new DateTimeOffset(2037, 10, 22, 0, 0, 0, TimeSpan.Zero));
            }

            if (revoked is { } r)
            {
                w.WriteGeneralizedTime(r);
            }

            w.WriteObjectIdentifier(oid);
            w.WriteCharacterString(UniversalTagNumber.IA5String, uri);
            using (w.PushSequence())
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1");
                }

                w.WriteOctetString(digest);
            }
        }
    }

    private static byte[] PolicyDocument(string oid, byte hashByte = 0xAA)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1");
            }

            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(oid);
                w.WriteGeneralizedTime(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
                using (w.PushSequence())
                {
                }

                w.WriteCharacterString(UniversalTagNumber.UTF8String, "test");
                using (w.PushSequence())
                {
                    using (w.PushSequence())
                    {
                        w.WriteGeneralizedTime(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
                    }
                }
            }

            w.WriteOctetString(Enumerable.Repeat(hashByte, 32).ToArray());
        }

        return w.Encode();
    }
}
