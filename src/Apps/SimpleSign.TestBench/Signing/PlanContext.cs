using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Signing;

/// <summary>A signature policy declared with the hash of an uploaded document, and the store that embeds the document.</summary>
internal sealed record UploadedPolicy(SignaturePolicyReference Policy, string PolicyCode, SignaturePolicyStore Store, string StoreCode);

/// <summary>
/// What every signing plan (PAdES, CAdES, XAdES) shares: the setup statements printed before the
/// builder chain, the HTTP provider, how the credential is passed, and the TSA options.
/// </summary>
internal sealed class PlanContext
{
    private readonly List<string> _setup = [];
    private readonly DocumentStore _documents;

    public PlanContext(EnvironmentMode environment, CredentialHandle credential, SandboxEnvironment sandbox, DocumentStore documents)
    {
        Credential = credential;
        _documents = documents;
        IsSandbox = environment == EnvironmentMode.Sandbox;
        Http = sandbox.HttpFor(environment);
    }

    public CredentialHandle Credential { get; }

    public bool IsSandbox { get; }

    public IHttpClientProvider Http { get; }

    /// <summary>Statements that must run before the builder chain (variables, clients).</summary>
    public IReadOnlyList<string> Setup => _setup;

    public void AddSetup(string statement) => _setup.Add(statement);

    /// <summary>The C# argument list of <c>WithCertificate</c> / <c>WithExternalSigner</c>, adding the setup that creates them.</summary>
    /// <returns>The builder call, e.g. <c>.WithCertificate(certificate, chain)</c>.</returns>
    public string CredentialCode()
    {
        if (Credential.External is not null)
        {
            string variable = Credential.Kind switch
            {
                CredentialKind.Pkcs11 => "token",
                _ => "csc",
            };
            _setup.Add(Credential.Kind switch
            {
                CredentialKind.Pkcs11 => "using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions { LibraryPath = libraryPath, TokenSerial = serial, Pin = pin });",
                _ => "var cscClient = new CscClient(new CscClientOptions { BaseUri = cscUrl, AccessToken = serviceToken });\n" +
                    "using var csc = await CscSigner.CreateAsync(cscClient, credentialId, new ExplicitCscAuthorizer(pin, otp));",
            });
            return $".WithExternalSigner({variable}.Certificate, {variable}, {variable}.Chain)";
        }

        _setup.Add(Credential.Kind switch
        {
            CredentialKind.Pfx => "var certificate = X509CertificateLoader.LoadPkcs12FromFile(\"signer.pfx\", password);",
            CredentialKind.OsStore => "var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)[0];",
            _ => "var certificate = sandboxSigner; // sandbox A1 certificate with its private key",
        });
        return Credential.Chain.Count > 0 ? ".WithCertificate(certificate, chain)" : ".WithCertificate(certificate)";
    }

    /// <summary>The HTTP provider line (sandbox only).</summary>
    public string HttpCode => IsSandbox
        ? ".WithHttpClientProvider(sandboxHttp) // TSA and CRLs on *.sandbox.simplesign.test"
        : "// default HttpClient provider (real network)";

    public TimestampOptions BuildTimestamp(TimestampChoice choice, string variable)
    {
        var endpoint = Endpoint(choice);
        var options = new TimestampOptions(endpoint, IsSandbox ? Http : null)
        {
            Authorization = Authorization(choice),
            ClientCertificate = ClientCertificate(choice),
        };
        _setup.Add($"var {variable} = new TimestampOptions(new Uri(\"{endpoint}\"){(IsSandbox ? ", sandboxHttp" : "")})"
            + (options.Authorization is null && options.ClientCertificate is null ? ";" :
                "\n{"
                + (choice.Auth == TsaAuth.Basic ? "\n    Authorization = new AuthenticationHeaderValue(\"Basic\", Convert.ToBase64String(Encoding.UTF8.GetBytes($\"{user}:{password}\"))),"
                    : choice.Auth == TsaAuth.Bearer ? "\n    Authorization = new AuthenticationHeaderValue(\"Bearer\", token)," : "")
                + (options.ClientCertificate is not null ? "\n    ClientCertificate = X509CertificateLoader.LoadPkcs12FromFile(\"tsa-client.pfx\", pfxPassword)," : "")
                + "\n};"));
        return options;
    }

    /// <summary>
    /// A custom signature policy whose document was uploaded: the policy reference with the
    /// SHA-256 of the file as its hash, the policy store that embeds the file, and their C#.
    /// </summary>
    public UploadedPolicy BuildUploadedPolicy(string oid, string? uri, string documentId, string specification)
    {
        var file = _documents.Get(documentId);
        _setup.Add($"byte[] policyDocument = File.ReadAllBytes({SigningPlan.Str(file.FileName)});");
        var policy = new SignaturePolicyReference(oid, Oids.Sha256, SHA256.HashData(file.Content), uri);
        var store = SignaturePolicyStore.FromDocument(specification, file.Content);
        return new UploadedPolicy(
            policy,
            $".WithSignaturePolicy(new SignaturePolicyReference({SigningPlan.Str(oid)}, Oids.Sha256, SHA256.HashData(policyDocument){(uri is null ? "" : ", " + SigningPlan.Str(uri))}))",
            store,
            $".WithSignaturePolicyStore(SignaturePolicyStore.FromDocument({SigningPlan.Str(store.Specification)}, policyDocument)) // the policy travels with the signature");
    }

    /// <summary>The name of an uploaded file, for the CLI command that takes it as a path.</summary>
    public string FileName(string documentId) => _documents.Get(documentId).FileName;

    /// <summary>An uploaded file, with the setup statement that reads it into <paramref name="variable"/>.</summary>
    public StoredFile Upload(string documentId, string variable)
    {
        var file = _documents.Get(documentId);
        _setup.Add($"byte[] {variable} = File.ReadAllBytes({SigningPlan.Str(file.FileName)});");
        return file;
    }

    /// <summary>The long-term validation options for a revocation preference.</summary>
    public LongTermValidationOptions BuildLongTerm(RevocationPreference preference) =>
        new(Http) { RevocationPreference = preference };

    /// <summary>The C# of <see cref="BuildLongTerm"/>.</summary>
    public string LongTermCode(RevocationPreference preference) =>
        $"new LongTermValidationOptions({(IsSandbox ? "sandboxHttp" : "")})"
        + (preference == RevocationPreference.CrlFirst ? " { RevocationPreference = RevocationPreference.CrlFirst }" : "");

    public ArchiveTimestampOptions BuildArchive(TimestampChoice choice)
    {
        var endpoint = Endpoint(choice);
        _setup.Add($"var archiveTsa = new ArchiveTimestampOptions(new Uri(\"{endpoint}\"){(IsSandbox ? ", sandboxHttp" : "")})"
            + (choice.Auth == TsaAuth.None ? ";" : " { Authorization = /* as above */ };"));
        return new ArchiveTimestampOptions(endpoint, IsSandbox ? Http : null)
        {
            Authorization = Authorization(choice),
            ClientCertificate = ClientCertificate(choice),
        };
    }

    /// <summary>The URL of a TSA choice, as the CLI's <c>--tsa</c> takes it.</summary>
    public static string CliUrl(TimestampChoice choice) => choice.Provider switch
    {
        TsaProvider.DigiCert => "http://timestamp.digicert.com",
        TsaProvider.Sectigo => "http://timestamp.sectigo.com",
        TsaProvider.FreeTsa => "https://freetsa.org/tsr",
        TsaProvider.Custom => choice.Url ?? "<tsa-url>",
        _ => "<tsa-url>",
    };

    internal static Uri Endpoint(TimestampChoice choice) => choice.Provider switch
    {
        TsaProvider.Sandbox => SandboxPki.TsaUri,
        TsaProvider.SandboxAuthenticated => SandboxPki.AuthenticatedTsaUri,
        TsaProvider.DigiCert => TimestampOptions.DigiCert.Endpoint,
        TsaProvider.Sectigo => TimestampOptions.Sectigo.Endpoint,
        TsaProvider.FreeTsa => TimestampOptions.FreeTsa.Endpoint,
        _ => new Uri(choice.Url!),
    };

    private static AuthenticationHeaderValue? Authorization(TimestampChoice choice) => choice.Auth switch
    {
        TsaAuth.Basic => new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{choice.User}:{choice.Password}"))),
        TsaAuth.Bearer => new AuthenticationHeaderValue("Bearer", choice.Token),
        _ => null,
    };

    private X509Certificate2? ClientCertificate(TimestampChoice choice) =>
        string.IsNullOrEmpty(choice.ClientCertificateUploadId)
            ? null
            : X509CertificateLoader.LoadPkcs12(_documents.Get(choice.ClientCertificateUploadId).Content, choice.ClientCertificatePassword,
                OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet);
}
