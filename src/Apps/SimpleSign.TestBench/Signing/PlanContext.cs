using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Signing;

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
                CredentialKind.Psc => "psc",
                _ => "csc",
            };
            _setup.Add(Credential.Kind switch
            {
                CredentialKind.Pkcs11 => "using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions { LibraryPath = libraryPath, TokenSerial = serial, Pin = pin });",
                CredentialKind.Psc => "var pscClient = new PscClient(new PscClientOptions { BaseUri = pscUrl, ClientId = clientId, ClientSecret = clientSecret });\n" +
                    "var pscToken = await pscClient.AuthorizeAsync(new LoopbackAuthorizationHandler(), PscScope.SignatureSession);\n" +
                    "using var psc = await PscSigner.CreateAsync(pscClient, pscToken);",
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
