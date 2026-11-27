using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Cli.Extensions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// Signs an XML document with a plain enveloped XML-DSig signature (no XAdES properties): an element by its Id, or the
/// whole document. The fiscal layouts of Brazil come with the <c>brasil</c> extension (<c>simplesign brasil fiscal sign</c>).
/// </summary>
[Description("Sign an XML document with a plain enveloped XML-DSig signature (an element by its Id, or the whole document)")]
internal sealed class XmlDsigSignCommand : AsyncCommand<XmlDsigSignCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;
    private string? _pfxPassword;

    public XmlDsigSignCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    /// <summary>XML-DSig sign command settings.</summary>
    internal sealed class Settings : PreparableSigningSettings
    {
        /// <summary>XML file to sign.</summary>
        [CommandArgument(0, "<input>")]
        [Description("XML file to sign")]
        public string InputPath { get; init; } = null!;

        /// <summary>PKCS#12 certificate file (.pfx/.p12).</summary>
        [CommandOption("--cert|-c <PATH>")]
        [Description("PKCS#12 certificate file (.pfx/.p12)")]
        public string? CertPath { get; init; }

        /// <summary>Certificate password (omit for interactive prompt).</summary>
        [CommandOption("--password|-p <PASSWORD>")]
        [Description("Certificate password (omit for interactive prompt)")]
        public string? Password { get; init; }

        /// <summary>PEM/DER file with intermediate CA certificates.</summary>
        [CommandOption("--chain <PATH>")]
        [Description("PEM/DER file with intermediate CA certificates (checked by the signing policy; KeyInfo carries the signer certificate only)")]
        public string? ChainPath { get; init; }

        /// <summary>Output signed XML file.</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("Output signed XML file (default: <input>.signed.xml)")]
        public string? OutputPath { get; init; }

        /// <summary>Local name of the element to sign by its Id; the whole document when absent.</summary>
        [CommandOption("--element <NAME>")]
        [Description("Local name of the element signed by its Id (e.g. infNFe), or * for any element with --id-attribute; default: the whole document (URI=\"\")")]
        public string? Element { get; init; }

        /// <summary>The Id attribute of the element.</summary>
        [CommandOption("--id-attribute <NAME>")]
        [Description("The attribute holding the element's Id (default: Id)")]
        public string? IdAttribute { get; init; }

        /// <summary>The Id of the element to sign when there are several.</summary>
        [CommandOption("--id <ID>")]
        [Description("The Id of the element to sign, when the document has several")]
        public string? ElementId { get; init; }

        /// <summary>Signs every unsigned element.</summary>
        [CommandOption("--all")]
        [Description("Sign every element of --element not signed yet (a batch)")]
        public bool All { get; init; }

        /// <summary>Where the signature goes.</summary>
        [CommandOption("--placement <PLACE>")]
        [Description("Where the signature goes: after-element (default) or end-of-root")]
        public string? Placement { get; init; }

        /// <summary>Hash algorithm.</summary>
        [CommandOption("--hash|-h <ALGORITHM>")]
        [Description("Hash algorithm: SHA256 (default), SHA384, SHA512, or SHA1 when the signing policy allows it")]
        public string? HashAlgorithm { get; init; }

        /// <summary>Canonicalization.</summary>
        [CommandOption("--canonicalization <C14N>")]
        [Description("Canonicalization of SignedInfo and of the reference: inclusive (C14N 1.0, default) or exclusive")]
        public string? Canonicalization { get; init; }

        /// <summary>Checks run before signing.</summary>
        [CommandOption("--signing-policy <PATH>")]
        [Description(SigningPolicyOption.Description)]
        public string? SigningPolicy { get; init; }

        /// <summary>Correlation id for the logs.</summary>
        [CommandOption("--operation-id <ID>")]
        [Description("Correlation id written in the logs and the audit record of this signature")]
        public string? OperationId { get; init; }

        /// <summary>Print the result (or the refusal) as one JSON object instead of text.</summary>
        [CommandOption("--json")]
        [Description("Print the result, or the refusal with its reason, as JSON")]
        public bool Json { get; init; }

        public override ValidationResult Validate()
        {
            string? error = !File.Exists(InputPath) ? $"File not found: {InputPath}"
                : !SigningPolicyOption.IsValid(SigningPolicy) ? SigningPolicyOption.Error(SigningPolicy)
                : CertPath is not null && !File.Exists(CertPath) ? $"Certificate file not found: {CertPath}"
                : ValidatePrepare(CertPath, otherCredential: false, Password, OutputPath)
                ?? ExternalCredentialSupport.Validate(this, CertPath is not null)
                ?? OwnError();
            return error is null ? ValidationResult.Success() : ValidationResult.Error(error);
        }

        private string? OwnError()
        {
            if (HashAlgorithm is not null && ParseHash(HashAlgorithm) is null)
            {
                return $"Invalid hash algorithm: {HashAlgorithm}. Valid: SHA1, SHA256, SHA384, SHA512";
            }

            if (Placement is not null && ParsePlacement(Placement) is null)
            {
                return $"Invalid placement: {Placement}. Valid: after-element, end-of-root";
            }

            if (Canonicalization is not null && ParseCanonicalization(Canonicalization) is null)
            {
                return $"Invalid canonicalization: {Canonicalization}. Valid: inclusive, exclusive";
            }

            if (Element is null && (IdAttribute ?? ElementId) is not null)
            {
                return "--id-attribute and --id need --element.";
            }

            if (All && ElementId is not null)
            {
                return "--all signs every element; --id signs one of them.";
            }

            return All && Prepare ? "--prepare makes one signature: use --id to choose the element instead of --all." : null;
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        SignJson.Enabled = settings.Json;
        byte[] xml = await CommonSettings.ReadInputBytesAsync(settings.InputPath, cancellationToken);

        using ExternalCredential? token = await ExternalCredentialSupport.OpenAsync(settings, cancellationToken);
        var (publicCert, publicChain) = settings.Prepare
            ? DeferredPrepareSupport.LoadCertificates(_certChainService, settings.CertPath!)
            : (null, []);
        using X509Certificate2? ownCert = publicCert ?? (token is null ? await LoadCertificateAsync(settings) : null);
        X509Certificate2 cert = token?.Certificate ?? ownCert!;

        List<X509Certificate2> chain = settings.Prepare ? publicChain : token is null ? PfxChain(settings, cert) : [.. token.Chain];
        if (settings.ChainPath is not null)
        {
            chain.AddRange(_certChainService.LoadCertsFromBytes(await File.ReadAllBytesAsync(settings.ChainPath, cancellationToken)));
        }

        var builder = XmlDsigSigner.Document(xml);
        builder = settings.Element is null ? builder : builder.WithSignedElement(settings.Element, settings.IdAttribute ?? "Id");
        builder = settings.ElementId is null ? builder : builder.WithElementId(settings.ElementId);
        builder = builder
            .WithPlacement(ParsePlacement(settings.Placement) ?? XmlDsigPlacement.AfterSignedElement)
            .WithHashAlgorithm(ParseHash(settings.HashAlgorithm) ?? HashAlgorithmName.SHA256)
            .WithCanonicalization(ParseCanonicalization(settings.Canonicalization) ?? XadesCanonicalization.Inclusive)
            .WithSigningPolicy(await settings.SigningPolicyAsync(settings.SigningPolicy, cancellationToken))
            .WithTrustAnchors(await settings.SigningTrustAnchorsAsync(cancellationToken));
        builder = token is null ? builder.WithCertificate(cert, chain) : builder.WithExternalSigner(token.Certificate, token.Signer, chain);
        builder = settings.OperationId is null ? builder : builder.WithOperationId(settings.OperationId);
        builder = settings.AuditSink() is { } audit ? builder.WithAuditSink(audit) : builder;
        builder = CliNetwork.IsConfigured ? builder.WithHttpClientProvider(CliNetwork.Provider) : builder;
        if (settings.CreateLogger<XmlDsigSignCommand>() is { } logger)
        {
            builder = builder.WithLogger(logger);
        }

        // What an extension's command adds (a fiscal layout, its policy): last, so it decides.
        if (SignScope.Current?.ConfigureXmlDsig is { } configure)
        {
            builder = await configure(builder, cancellationToken);
        }

        if (settings.Prepare)
        {
            var prepared = await XmlDsigDeferredSigner.From(builder).WithSessionIntegrityKey(DeferredSessionKey.Parse(settings.SessionKey)!)
                .PrepareAsync(cancellationToken);
            return await DeferredPrepareSupport.WriteAsync(
                settings, settings.InputPath, "xmldsig", prepared.SessionData, prepared.DataToSign,
                prepared.DigestAlgorithm, prepared.SignatureAlgorithmOid, settings.Json, cancellationToken);
        }

        byte[] signed = settings.All || SignScope.Current is { SignAll: true }
            ? await builder.SignAllAsync(cancellationToken)
            : await builder.SignAsync(cancellationToken);
        string outputPath = settings.OutputPath ?? settings.InputPath + ".signed.xml";
        await File.WriteAllBytesAsync(outputPath, signed, cancellationToken);
        if (settings.Json)
        {
            SignJson.WriteSuccess("xmldsig", outputPath, cert.Subject);
            return 0;
        }

        AnsiConsole.MarkupLine($"[green]XML-DSig signature saved to:[/] {outputPath.EscapeMarkup()}");
        return 0;
    }

    private async Task<X509Certificate2> LoadCertificateAsync(Settings settings)
    {
        if (settings.CertPath is null)
        {
            throw new InvalidOperationException("No certificate: use --cert, --thumbprint, --pkcs11-lib, --psc-url or --csc-url.");
        }

        _pfxPassword = settings.Password ?? await PasswordResolver.ResolveAsync(settings.Password, isInteractive: true);
        return _certChainService.LoadPkcs12FromFile(settings.CertPath, _pfxPassword);
    }

    /// <summary>The other certificates of the --cert PFX (its chain).</summary>
    private List<X509Certificate2> PfxChain(Settings settings, X509Certificate2 signer)
    {
        if (settings.CertPath is null)
        {
            return [];
        }

        List<X509Certificate2> chain = [];
        foreach (var certificate in _certChainService.LoadPkcs12CollectionFromFile(settings.CertPath, _pfxPassword ?? settings.Password))
        {
            if (certificate.Thumbprint == signer.Thumbprint)
            {
                certificate.Dispose();
            }
            else
            {
                chain.Add(certificate);
            }
        }

        return chain;
    }

    internal static HashAlgorithmName? ParseHash(string? value) =>
        value?.Replace("-", string.Empty, StringComparison.Ordinal).ToUpperInvariant() == "SHA1" ? HashAlgorithmName.SHA1 : HashAlgorithmHelper.TryParse(value);

    private static XmlDsigPlacement? ParsePlacement(string? value) => value?.ToLowerInvariant() switch
    {
        "after-element" => XmlDsigPlacement.AfterSignedElement,
        "end-of-root" => XmlDsigPlacement.LastChildOfRoot,
        _ => null,
    };

    private static XadesCanonicalization? ParseCanonicalization(string? value) => value?.ToLowerInvariant() switch
    {
        "inclusive" or "c14n" => XadesCanonicalization.Inclusive,
        "exclusive" or "exc-c14n" => XadesCanonicalization.Exclusive,
        _ => null,
    };
}
