using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Policies;

namespace SimpleSign.TestBench.Documents;

/// <summary>
/// Files a run can name without uploading them, under fixed ids (<c>fixture:NAME</c>) like the built-in policies:
/// a signature-policy document (for the signature-policy-store), an X.509 attribute certificate (a certified role) and a
/// SAML assertion (a signed assertion about the signer). Playbooks use them as option values.
/// </summary>
internal static class Fixtures
{
    /// <summary>The id of a fixture.</summary>
    public static string Id(string name) => "fixture:" + name;

    /// <summary>The fixtures: id, file name and what it is.</summary>
    public static IReadOnlyList<(string Id, string FileName, string Title)> All { get; } =
    [
        (Id("signature-policy"), "signature-policy.xml", "A signature-policy document (for the signature-policy-store)"),
        (Id("attribute-certificate"), "role.ac", "An X.509 attribute certificate (RFC 5755) with the role 'Legal representative'"),
        (Id("saml-assertion"), "assertion.xml", "A SAML 2.0 assertion about the signer"),
        (Id("validation-policy-en319422"), "validation-policy-en319422.json",
            "A validation policy with the EN 319 422 time-stamp profile: accuracy given, no ordering, the Sandbox TSA's policy"),
    ];

    /// <summary>The policy OID the Sandbox's TSA writes in its time-stamps.</summary>
    public const string SandboxTsaPolicy = "1.3.6.1.4.1.99999.3161.1";

    /// <summary>Adds every fixture to <paramref name="documents"/>, under its id.</summary>
    public static void AddTo(DocumentStore documents)
    {
        documents.AddFixed(All[0].Id, All[0].FileName, Encoding.UTF8.GetBytes(SignaturePolicy));
        documents.AddFixed(All[1].Id, All[1].FileName, AttributeCertificate());
        documents.AddFixed(All[2].Id, All[2].FileName, Encoding.UTF8.GetBytes(SamlAssertion));
        var fail = new PolicyConstraint(ConstraintLevel.Fail);
        var en319422 = ValidationPolicy.Default
            .WithName("SimpleSign default + EN 319 422 time-stamp profile")
            .With("Timestamp/AccuracyPresent", fail)
            .With("Timestamp/OrderingFalse", fail)
            .With("Timestamp/AcceptablePolicies", new PolicyConstraint(ConstraintLevel.Fail) { Ids = [SandboxTsaPolicy] });
        documents.AddFixed(All[3].Id, All[3].FileName, Encoding.UTF8.GetBytes(en319422.ToJson()));
    }

    private const string SignaturePolicy = """
        <?xml version="1.0" encoding="UTF-8"?>
        <SignaturePolicy xmlns="urn:simplesign:testbench:policy">
          <Identifier>1.3.6.1.4.1.99999.1.1</Identifier>
          <Title>SimpleSign TestBench sample signature policy</Title>
          <Description>A stand-in policy document: its hash goes into the signature-policy-identifier and the file into the
            signature-policy-store, so a validator can read the policy offline.</Description>
        </SignaturePolicy>
        """;

    private const string SamlAssertion = """
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="simplesign-testbench-assertion" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
          <saml:Issuer>urn:simplesign:testbench:attribute-authority</saml:Issuer>
          <saml:Subject><saml:NameID>Maria da Silva</saml:NameID></saml:Subject>
          <saml:AttributeStatement>
            <saml:Attribute Name="role"><saml:AttributeValue>Legal representative</saml:AttributeValue></saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
        """;

    /// <summary>
    /// An RFC 5755 attribute certificate with the role attribute (2.5.4.72), issued by a throwaway attribute authority
    /// key: structurally valid, so signers embed it and validators read it; its signature is not meant to be trusted.
    /// </summary>
    private static byte[] AttributeCertificate()
    {
        using var key = RSA.Create(2048);
        var holder = new X500DistinguishedName("CN=Maria da Silva, O=SimpleSign Sandbox, C=BR");
        var issuer = new X500DistinguishedName("CN=SimpleSign TestBench Attribute Authority, O=SimpleSign Sandbox, C=BR");
        const string sha256WithRsa = "1.2.840.113549.1.1.11";

        var info = new AsnWriter(AsnEncodingRules.DER);
        using (info.PushSequence())
        {
            info.WriteInteger(1); // v2
            using (info.PushSequence()) // Holder
            {
                using (info.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1))) // entityName [1] GeneralNames
                {
                    DirectoryName(info, holder);
                }
            }

            using (info.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0))) // v2Form [0] V2Form
            {
                using (info.PushSequence()) // issuerName GeneralNames
                {
                    DirectoryName(info, issuer);
                }
            }

            Algorithm(info, sha256WithRsa);
            info.WriteInteger(1);
            using (info.PushSequence()) // attrCertValidityPeriod
            {
                info.WriteGeneralizedTime(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
                info.WriteGeneralizedTime(new DateTimeOffset(2036, 1, 1, 0, 0, 0, TimeSpan.Zero));
            }

            using (info.PushSequence()) // attributes
            {
                using (info.PushSequence())
                {
                    info.WriteObjectIdentifier("2.5.4.72"); // id-at-role
                    using (info.PushSetOf())
                    {
                        using (info.PushSequence()) // RoleSyntax
                        {
                            using (info.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))) // roleName [1] GeneralName
                            {
                                info.WriteCharacterString(UniversalTagNumber.IA5String, "urn:simplesign:role:legal-representative",
                                    new Asn1Tag(TagClass.ContextSpecific, 6)); // uniformResourceIdentifier [6]
                            }
                        }
                    }
                }
            }
        }

        byte[] tbs = info.Encode();
        var certificate = new AsnWriter(AsnEncodingRules.DER);
        using (certificate.PushSequence())
        {
            certificate.WriteEncodedValue(tbs);
            Algorithm(certificate, sha256WithRsa);
            certificate.WriteBitString(key.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        return certificate.Encode();
    }

    private static void DirectoryName(AsnWriter writer, X500DistinguishedName name)
    {
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true))) // directoryName [4] EXPLICIT Name
        {
            writer.WriteEncodedValue(name.RawData);
        }
    }

    private static void Algorithm(AsnWriter writer, string oid)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteNull();
        }
    }
}
