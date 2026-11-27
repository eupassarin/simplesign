using System.Text;
using SimpleSign.Brazil.Fiscal;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Signing;
using SimpleSign.XAdES;

namespace SimpleSign.TestBench.Xml;

/// <summary>
/// The signature of a fiscal layout (<see cref="XadesKind.Fiscal"/>): <c>FiscalXmlSigner.Document</c> with the run's
/// credential, signing policy and trust, as C#, as <c>simplesign brasil fiscal sign</c>, and the builder that makes it.
/// </summary>
internal sealed class FiscalPlan
{
    private readonly XmlOptions _o;
    private readonly PlanContext _context;
    private readonly List<(string Code, Func<XmlDsigSignerBuilder, XmlDsigSignerBuilder> Apply)> _steps = [];

    public FiscalPlan(XmlOptions o, PlanContext context)
    {
        _o = o;
        _context = context;
        Layout = XmlCompatibility.FiscalLayout(o.FiscalLayout) ?? throw new ArgumentException(L.T("Unknown fiscal layout."));
        var credential = context.Credential;
        _steps.Add(credential.External is { } external
            ? (context.CredentialCode(), b => b.WithExternalSigner(credential.Certificate, external, credential.Chain))
            : (context.CredentialCode(), b => b.WithCertificate(credential.Certificate, credential.Chain)));
        if (context.IsSandbox)
        {
            _steps.Add((context.HttpCode, b => b.WithHttpClientProvider(context.Http)));
        }

        // The layout's policy (FiscalPolicies.Sefaz with SHA-1, IcpBrasilPolicies.Signing otherwise) unless the run names one.
        var signingPolicy = PolicyUploads.Signing(o.SigningPolicyId, context.Documents);
        if (signingPolicy.Error is { } policyError)
        {
            throw new ArgumentException(L.T("The signing policy cannot be read: {0}", policyError));
        }

        var controls = context.Controls;
        bool byProfile = controls.ProfileSetsPolicy(o.SigningPolicyId);
        if (signingPolicy.Uploaded)
        {
            _steps.Add(byProfile
                ? (controls.ProfileStepCode(), b => b.WithSigningPolicy(signingPolicy.Policy).WithTrustAnchors([.. controls.ProfileAnchors]))
                : (PolicyUploads.SigningCode(signingPolicy), b => b.WithSigningPolicy(signingPolicy.Policy)));
        }

        if (controls.TrustCode(byProfile) is { } trustCode)
        {
            _steps.Add((trustCode, b => b.WithTrustAnchors([.. byProfile ? controls.OtherAnchors : controls.Anchors])));
        }

        if (controls.Audit is { } audit)
        {
            _steps.Add((controls.AuditCode()!, b => b.WithAuditSink(audit)));
        }

        if (!string.IsNullOrWhiteSpace(o.OperationId))
        {
            string id = o.OperationId.Trim();
            _steps.Add(($".WithOperationId({SigningPlan.Str(id)})", b => b.WithOperationId(id)));
        }
    }

    /// <summary>The fiscal layout.</summary>
    public FiscalDocumentProfile Layout { get; }

    /// <summary>The name of the layout in the API (<c>FiscalDocumentProfile.NFe</c>…).</summary>
    private string LayoutCode => _o.FiscalLayout.ToLowerInvariant() switch
    {
        "nfe" or "nfce" => "NFe",
        "evento" => "Evento",
        "inutilizacao" => "Inutilizacao",
        "cte" => "CTe",
        "mdfe" => "MDFe",
        "nfse" => "NFSeDps",
        "esocial" => "ESocial",
        _ => "Reinf",
    };

    /// <summary>The one-call builder of <paramref name="xml"/>, with every step applied.</summary>
    public XmlDsigSignerBuilder Builder(byte[] xml)
    {
        var builder = FiscalXmlSigner.Document(xml, Layout).WithLogger(RunLog.Logger);
        foreach (var (_, apply) in _steps)
        {
            builder = apply(builder);
        }

        return builder;
    }

    public CodeSnippets Code()
    {
        var sb = new StringBuilder("using SimpleSign.Brazil.Fiscal;\nusing SimpleSign.XAdES;\n\n");
        if (_context.IsSandbox)
        {
            sb.Append("// The SimpleSign Sandbox runs on this machine: sandboxHttp (below) lets the library reach it.\n");
        }

        sb.Append("byte[] xml = File.ReadAllBytes(\"document.xml\");\n");
        foreach (string line in _context.Setup.Distinct())
        {
            sb.Append(line).Append('\n');
        }

        string entry = $"(xml, FiscalDocumentProfile.{LayoutCode})";
        sb.Append(LayoutComment());
        if (_o.TwoPhases)
        {
            TwoPhaseSupport.AppendCSharp(
                sb, "FiscalXmlSigner.Deferred" + entry, _steps.Select(s => s.Code), "XmlDsigDeferredSigner.Resume", new ResumeInputs([], null, null, [], null, null),
                "byte[]", "the canonical ds:SignedInfo", Layout.HashAlgorithm.Name!, pss: false);
            sb.Replace("    .CompleteWithDetailsAsync(signature);", "    .CompleteAsync(signature);");
            sb.Append("File.WriteAllBytes(\"signed.xml\", result);\n");
        }
        else
        {
            sb.Append("\nbyte[] signed = await FiscalXmlSigner.Document").Append(entry).Append('\n');
            foreach (var (code, _) in _steps)
            {
                sb.Append("    ").Append(code).Append('\n');
            }

            sb.Append("    .SignAsync(); // SignAllAsync() signs every element of a batch\n\n");
            sb.Append("File.WriteAllBytes(\"signed.xml\", signed);\n");
        }

        var notes = new List<string>();
        var cli = new CliLine("brasil", "fiscal", "sign", XmlRunner.DataFile).Add("--layout", _o.FiscalLayout.ToLowerInvariant());
        if (_o.TwoPhases)
        {
            TwoPhaseSupport.Prepare(cli);
        }
        else
        {
            cli.Add("--output", XmlRunner.SignedFile);
            CodeGenerator.CliCredential(_context.Credential.Facts, cli, notes);
        }

        // brasil fiscal sign applies the layout's policy unless --signing-policy names one: the profile's preset is named too.
        if (_o.SigningPolicyId is not null)
        {
            cli.Add("--signing-policy", _context.Controls.ProfileSetsPolicy(_o.SigningPolicyId)
                ? _o.SigningPolicyId[(_o.SigningPolicyId.LastIndexOf(':') + 1)..]
                : PolicyUploads.SigningFileName);
        }

        _context.Controls.Cli(cli);
        cli.AddIf("--operation-id", _o.OperationId);
        _context.CliNetwork(cli);
        if (_o.TwoPhases)
        {
            IReadOnlyList<CliLine> commands =
            [
                cli,
                TwoPhaseSupport.Complete(XmlRunner.DataFile, XmlRunner.SignedFile, _context, null, _o.SigningPolicyId, notes),
            ];
            return new CodeSnippets(sb.ToString(), CliLine.Join(commands), notes) { CliCommands = commands };
        }

        return new CodeSnippets(sb.ToString(), cli.ToString(), notes) { CliCommands = [cli] };
    }

    private string LayoutComment() =>
        $"// {Layout.Name}: {(Layout.SignedElement is null ? "the whole document" : Layout.SignedElement + " by its " + Layout.IdAttribute)}, RSA-{Layout.HashAlgorithm.Name}, under ICP-Brasil (FiscalPolicies.Sefaz for SHA-1).\n";
}
