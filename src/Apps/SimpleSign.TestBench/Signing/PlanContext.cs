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

    private readonly SandboxEnvironment _sandbox;

    /// <summary>The uploads and documents of the workbench.</summary>
    public DocumentStore Documents { get; }

    public PlanContext(CredentialHandle credential, SandboxEnvironment sandbox, DocumentStore documents)
    {
        Documents = documents;
        Credential = credential;
        _documents = documents;
        _sandbox = sandbox;
        IsSandbox = sandbox.Current is not null;
        Http = sandbox;
        if (sandbox.Current is { } connection)
        {
            string origins = string.Join(", ", connection.Info.LoopbackOrigins.Select(o => $"new Uri(\"{o}\")"));
            _setup.Add("// The local SimpleSign Sandbox: list its origins so the SSRF guard lets them through, and trust its root for HTTPS.\n"
                + "var sandboxHttp = new SingleClientProvider(new HttpClient(handlerTrustingTheSandboxRoot))\n{\n"
                + "    OutboundPolicy = new OutboundHttpPolicy\n    {\n        AllowLdap = true,\n"
                + $"        LoopbackOrigins = [{origins}],\n"
                + "    },\n};");
        }
    }

    public CredentialHandle Credential { get; }

    /// <summary>The trust anchors, expected TSA and audit trail of the run.</summary>
    public SigningControls Controls { get; init; } = SigningControls.None;

    /// <summary>Whether a Sandbox is connected: the generated code then builds the provider that reaches it.</summary>
    public bool IsSandbox { get; }

    /// <summary>The TestBench's network: the real one, plus the connected Sandbox.</summary>
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
            _ => "var certificate = X509CertificateLoader.LoadPkcs12FromFile(\"sandbox-signer.pfx\", \"sandbox\"); // downloaded from the Sandbox's PKI page",
        });
        return Credential.Chain.Count > 0 ? ".WithCertificate(certificate, chain)" : ".WithCertificate(certificate)";
    }

    /// <summary>The HTTP provider line (when a Sandbox is connected).</summary>
    public string HttpCode => IsSandbox
        ? ".WithHttpClientProvider(sandboxHttp) // reaches the local Sandbox's TSA, CRLs and OCSP"
        : "// default HttpClient provider (real network)";

    public TimestampOptions BuildTimestamp(TimestampChoice choice, string variable)
    {
        var endpoint = Endpoint(choice);
        var options = new TimestampOptions(endpoint, Http)
        {
            Authorization = Authorization(choice),
            ClientCertificate = ClientCertificate(choice),
            ExpectedTsaCertificate = Controls.ExpectedTsa,
        };
        _setup.Add($"var {variable} = new TimestampOptions(new Uri(\"{endpoint}\"){(IsSandbox ? ", sandboxHttp" : "")})"
            + (options.Authorization is null && options.ClientCertificate is null && options.ExpectedTsaCertificate is null ? ";" :
                "\n{"
                + (choice.Auth == TsaAuth.Basic ? "\n    Authorization = new AuthenticationHeaderValue(\"Basic\", Convert.ToBase64String(Encoding.UTF8.GetBytes($\"{user}:{password}\"))),"
                    : choice.Auth == TsaAuth.Bearer ? "\n    Authorization = new AuthenticationHeaderValue(\"Bearer\", token)," : "")
                + (options.ClientCertificate is not null ? "\n    ClientCertificate = X509CertificateLoader.LoadPkcs12FromFile(\"tsa-client.pfx\", pfxPassword)," : "")
                + (Controls.ExpectedTsaCode() is { } expected ? "\n    " + expected : "")
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
        return new ArchiveTimestampOptions(endpoint, Http)
        {
            Authorization = Authorization(choice),
            ClientCertificate = ClientCertificate(choice),
            ExpectedTsaCertificate = Controls.ExpectedTsa,
        };
    }

    /// <summary>
    /// The network flags a CLI command needs to reach the connected Sandbox: its HTTP loopback origins
    /// (<c>--allow-origin</c>) and LDAP. Nothing without a Sandbox.
    /// </summary>
    public void CliNetwork(CliLine line) => SandboxNetwork(line, _sandbox);

    /// <summary>The flags a CLI command needs for the connected Sandbox, if any: its origins (<c>--allow-origin</c>), LDAP and its root for HTTPS.</summary>
    internal static void SandboxNetwork(CliLine line, SandboxEnvironment sandbox)
    {
        if (sandbox.Current is not { } connection)
        {
            return;
        }

        // Every origin of the Sandbox: HTTP, HTTPS (with its root below) and LDAP.
        foreach (var origin in connection.Info.LoopbackOrigins)
        {
            line.Add("--allow-origin", origin);
        }

        // Its CRLs over LDAP, and its HTTPS endpoints (CRLs over HTTPS) under its own root.
        line.Add("--allow-ldap");
        line.Add("--tls-trust", connection.RootPemFile());
    }

    /// <summary>
    /// The CLI flags of a TSA choice: <c>--tsa</c> (or <c>--archive-tsa</c>) and, for the signature TSA, its
    /// credentials. Secrets appear as variables, except the Sandbox's own published test password.
    /// </summary>
    public void CliTimestamp(CliLine line, TimestampChoice choice, bool archive = false)
    {
        line.Add(archive ? "--archive-tsa" : "--tsa", CliUrl(choice));
        if (archive)
        {
            return;
        }

        Controls.CliTimestamp(line);

        if (choice.Provider == TsaProvider.SandboxAuthenticated && _sandbox.Current is { } connection)
        {
            line.Add("--tsa-user", connection.Info.Tsa.User).Add("--tsa-password", connection.Info.Tsa.Password);
        }
        else if (choice.Auth == TsaAuth.Basic)
        {
            line.Add("--tsa-user", choice.User ?? "").Add("--tsa-password", CliLine.Placeholders.TsaPassword);
        }
        else if (choice.Auth == TsaAuth.Bearer)
        {
            line.Add("--tsa-token", CliLine.Placeholders.TsaToken);
        }

        if (!string.IsNullOrEmpty(choice.ClientCertificateUploadId))
        {
            line.Add("--tsa-cert", CliLine.Placeholders.TsaClientPfx).Add("--tsa-cert-password", CliLine.Placeholders.TsaClientPassword);
        }
    }

    /// <summary>The URL of a TSA choice, as the CLI's <c>--tsa</c> takes it.</summary>
    public string CliUrl(TimestampChoice choice) => choice.Provider switch
    {
        TsaProvider.DigiCert => "http://timestamp.digicert.com",
        TsaProvider.Sectigo => "http://timestamp.sectigo.com",
        TsaProvider.FreeTsa => "https://freetsa.org/tsr",
        TsaProvider.Custom => choice.Url ?? "<tsa-url>",
        _ when SharedRules.IsSandboxTsa(choice.Provider) && _sandbox.Current is not null => Endpoint(choice).AbsoluteUri,
        _ => "<tsa-url>",
    };

    /// <summary>The TSA URL of a choice; the Sandbox's TSAs come from the connected Sandbox.</summary>
    /// <exception cref="SandboxNotConnectedException">A Sandbox TSA was chosen and no Sandbox is connected.</exception>
    internal Uri Endpoint(TimestampChoice choice) => choice.Provider switch
    {
        TsaProvider.Sandbox => _sandbox.Connection.TsaUri,
        TsaProvider.SandboxAuthenticated => _sandbox.Connection.AuthenticatedTsaUri,
        TsaProvider.SandboxUntrusted => _sandbox.Connection.UntrustedTsaUri,
        TsaProvider.SandboxRevoked => _sandbox.Connection.RevokedTsaUri,
        TsaProvider.SandboxExpired => _sandbox.Connection.ExpiredTsaUri,
        TsaProvider.SandboxWrongName => _sandbox.Connection.WrongNameTsaUri,
        TsaProvider.SandboxShortLived => _sandbox.Connection.ShortLivedTsaUri,
        TsaProvider.SandboxIofe => _sandbox.Connection.IofeTsaUri,
        TsaProvider.SandboxNonQualified => _sandbox.Connection.NonQualifiedTsaUri,
        TsaProvider.DigiCert => TimestampOptions.DigiCert.Endpoint,
        TsaProvider.Sectigo => TimestampOptions.Sectigo.Endpoint,
        TsaProvider.FreeTsa => TimestampOptions.FreeTsa.Endpoint,
        _ => new Uri(choice.Url!),
    };

    private AuthenticationHeaderValue? Authorization(TimestampChoice choice) => choice.Provider == TsaProvider.SandboxAuthenticated
        // The Sandbox's authenticated TSA: its own test credentials.
        ? new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_sandbox.Connection.Info.Tsa.User}:{_sandbox.Connection.Info.Tsa.Password}")))
        : choice.Auth switch
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
