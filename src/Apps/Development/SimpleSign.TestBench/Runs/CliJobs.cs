using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Runs;

/// <summary>
/// Builds a <see cref="CliJob"/> from a run: the signer's files and password, the TSA's credentials, the signing
/// policy and every upload the options name, under the file names the generated commands use.
/// </summary>
internal sealed class CliJobs
{
    private readonly Dictionary<string, byte[]> _files = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _secrets = new(StringComparer.Ordinal);

    /// <summary>Why the CLI cannot sign with this credential (a token or a cloud credential), or null when it can.</summary>
    public static string? Unsupported(CredentialHandle credential) =>
        credential.Cli is not null || credential.Kind == CredentialKind.OsStore
            ? null
            : L.T("A run through the CLI needs a PFX, a Sandbox certificate or a certificate of the OS store; this credential ({0}) can only be used through the library.", credential.Kind);

    /// <summary>Adds a file the commands name.</summary>
    public CliJobs File(string name, byte[] content)
    {
        _files[name] = content;
        return this;
    }

    /// <summary>The signer: its PKCS#12 and password, its certificate and its chain (for <c>deferred prepare</c>).</summary>
    public CliJobs Credential(CredentialHandle credential)
    {
        if (credential.Cli is { } cli)
        {
            _files[CliLine.Placeholders.SignerPfx] = cli.Pfx;
            _secrets[CliLine.Placeholders.PfxPassword] = cli.Password;
        }

        _files[CliLine.Placeholders.SignerCertificate] = credential.Certificate.Export(X509ContentType.Cert);
        _files[CliLine.Placeholders.Chain] = Encoding.ASCII.GetBytes(string.Concat(credential.Chain.Select(c => c.ExportCertificatePem() + "\n")));
        return this;
    }

    /// <summary>The credentials of a TSA choice: user password, bearer token, client certificate and its password.</summary>
    public CliJobs Timestamp(TimestampChoice? choice, DocumentStore documents)
    {
        if (choice is null)
        {
            return this;
        }

        _secrets[CliLine.Placeholders.TsaPassword] = choice.Password ?? "";
        _secrets[CliLine.Placeholders.TsaToken] = choice.Token ?? "";
        if (!string.IsNullOrEmpty(choice.ClientCertificateUploadId) && documents.TryGet(choice.ClientCertificateUploadId, out var pfx))
        {
            _files[CliLine.Placeholders.TsaClientPfx] = pfx!.Content;
            _secrets[CliLine.Placeholders.TsaClientPassword] = choice.ClientCertificatePassword ?? "";
        }

        return this;
    }

    /// <summary>
    /// Every upload the options name (signature policy documents, attribute certificates, data objects…), under its own
    /// file name as the generated commands use it, and the signing policy under <see cref="PolicyUploads.SigningFileName"/>.
    /// </summary>
    public CliJobs Uploads<T>(T options, string? signingPolicyId, DocumentStore documents)
    {
        foreach (string id in Strings(JsonSerializer.SerializeToElement(options, WorkbenchJson.Options)))
        {
            if (documents.TryGet(id, out var file) && !_files.ContainsKey(file!.FileName))
            {
                _files[file.FileName] = file.Content;
            }
        }

        if (signingPolicyId is not null && documents.TryGet(signingPolicyId, out var policy))
        {
            _files[PolicyUploads.SigningFileName] = policy!.Content;
        }

        return this;
    }

    /// <summary>The job: <paramref name="commands"/>, the files and secrets added, and a fresh session key for a deferred signature.</summary>
    public CliJob Build(IReadOnlyList<CliLine> commands, Func<CliLine, string, CancellationToken, Task>? beforeCommand = null)
    {
        _secrets[CliLine.Placeholders.SessionKey] = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        return new CliJob(commands, _files, _secrets, beforeCommand);
    }

    private static IEnumerable<string> Strings(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => [element.GetString()!],
        JsonValueKind.Object => element.EnumerateObject().SelectMany(p => Strings(p.Value)),
        JsonValueKind.Array => element.EnumerateArray().SelectMany(Strings),
        _ => [],
    };
}
