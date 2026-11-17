using System.ComponentModel;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Brazil.Signing;
using SimpleSign.Cli.Extensibility;
using SimpleSign.PAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Brazil.Cli;

/// <summary>
/// <c>simplesign brasil sign</c>: the standard <c>simplesign sign</c>, every option of it, plus what is Brazilian — an
/// ICP-Brasil PAdES policy (<c>--icp-policy</c>), an advanced electronic signature of Lei 14.063 (<c>--aea</c>) and a
/// VALIDAR health document (<c>--health-document</c>).
/// </summary>
[Description("Sign a PDF as 'simplesign sign' does (every option of it is accepted), plus the Brazilian options below")]
internal sealed class BrasilSignCommand : AsyncCommand<BrasilSignCommand.Settings>
{
    /// <summary>The Brazilian options; the arguments of <c>simplesign sign</c> follow them.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>Advanced Electronic Signature (AEA) per Lei 14.063/2020.</summary>
        [CommandOption("--aea|--brasil")]
        [Description("Advanced Electronic Signature (AEA) per Lei 14.063/2020: needs --cpf and --signer-name, and reads --auth-method, --signer-email, --institution, --commitment, --policy-oid and --policy-uri")]
        public bool Aea { get; init; }

        /// <summary>CPF (11 digits, no punctuation) for AEA.</summary>
        [CommandOption("--cpf <CPF>")]
        [Description("With --aea: the signer's CPF (11 digits, no punctuation)")]
        public string? Cpf { get; init; }

        /// <summary>Institution CNPJ (14 digits) for AEA.</summary>
        [CommandOption("--institution-cnpj <CNPJ>")]
        [Description("With --aea: the CNPJ (14 digits) of the institution of --institution")]
        public string? InstitutionCnpj { get; init; }

        /// <summary>ICP-Brasil PAdES signature policy: ad-rb, ad-rt, ad-rc or ad-ra.</summary>
        [CommandOption("--icp-policy <POLICY>")]
        [Description("ICP-Brasil PAdES policy: ad-rb, ad-rt, ad-rc or ad-ra; the version follows the signer's root, and the policy sets the level and the PBAD.PAdES sub-filter (all but ad-rb require --tsa; ad-ra downloads the PA and LPA from the ITI)")]
        public string? IcpPolicy { get; init; }

        /// <summary>VALIDAR health document type.</summary>
        [CommandOption("--health-document <TYPE>")]
        [Description("Health document for VALIDAR: prescricao, atestado, exame or relatorio (requires --registration)")]
        public string? HealthDocument { get; init; }

        /// <summary>Professional registrations, COUNCIL:NUMBER/UF.</summary>
        [CommandOption("--registration <COUNCIL:NUMBER/UF>")]
        [Description("Professional registration for --health-document, e.g. crm:123456/SP (repeatable)")]
        public string[]? Registrations { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate() =>
            OwnError() is { } error ? ValidationResult.Error(error) : ValidationResult.Success();

        /// <summary>The error of the Brazilian options on their own, or null.</summary>
        private string? OwnError()
        {
            if (IcpPolicy is not null && IcpBrasilCliOptions.ParsePolicy(IcpPolicy) is null)
            {
                return "--icp-policy must be ad-rb, ad-rt, ad-rc or ad-ra.";
            }

            if (HealthDocument is not null)
            {
                if (IcpBrasilCliOptions.ParseHealthDocument(HealthDocument) is null)
                {
                    return "--health-document must be prescricao, atestado, exame or relatorio.";
                }

                if (Registrations is not { Length: > 0 })
                {
                    return "--health-document requires at least one --registration (e.g. crm:123456/SP).";
                }
            }

            if ((Registrations ?? []).FirstOrDefault(r => IcpBrasilCliOptions.ParseRegistration(r) is null) is { } registration)
            {
                return $"--registration '{registration}' must be COUNCIL:NUMBER/UF, e.g. crm:123456/SP.";
            }

            if (Aea && string.IsNullOrWhiteSpace(Cpf))
            {
                return "--aea requires --cpf.";
            }

            return !Aea && (Cpf ?? InstitutionCnpj) is not null ? "--cpf and --institution-cnpj are for --aea." : null;
        }

        /// <summary>The error of the standard options of <c>sign</c> next to the Brazilian ones, or null.</summary>
        internal string? StandardError(CliSignOptions sign)
        {
            if (IcpBrasilCliOptions.ParsePolicy(IcpPolicy) is { } policy)
            {
                if (policy != IcpBrasilPolicy.AdRb && sign.Timestamp is null)
                {
                    return $"--icp-policy {IcpPolicy!.ToLowerInvariant()} requires --tsa (an ICP-Brasil ACT).";
                }

                if (sign.SubFilter is not null)
                {
                    return "--icp-policy sets the PBAD.PAdES sub-filter the ICP-Brasil PAs mandate; remove --sub-filter.";
                }

                if (sign.LongTerm || sign.Archival)
                {
                    return "--icp-policy sets the level: use ad-rc or ad-ra for the DSS and document timestamp instead of --ltv/--archival.";
                }

                if (sign.PolicyOid is not null)
                {
                    return "--icp-policy and --policy-oid are mutually exclusive.";
                }
            }

            if (HealthDocument is not null && sign.ExistingField is not null)
            {
                return "--health-document cannot be used with --existing-field.";
            }

            if (sign.PolicyHash is not null && (Aea || IcpPolicy is not null))
            {
                return "--policy-hash is for an explicit policy; --aea and --icp-policy set their own.";
            }

            return Aea ? AeaError(sign) : null;
        }

        private static string? AeaError(CliSignOptions sign)
        {
            if (string.IsNullOrWhiteSpace(sign.SignerName))
            {
                return "--aea requires --signer-name.";
            }

            if (sign.AuthMethod is not null && !BrasilSignOptions.IsAuthMethod(sign.AuthMethod))
            {
                return "--auth-method must be digital-certificate, gov-br, institutional-login, facial-biometrics, token-otp, or username-password.";
            }

            return sign.Commitment is not null
                && !sign.Commitment.Equals("approval", StringComparison.OrdinalIgnoreCase)
                && !sign.Commitment.Equals("origin", StringComparison.OrdinalIgnoreCase)
                    ? "--commitment must be approval or origin."
                    : null;
        }
    }

    /// <inheritdoc />
    public override Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken) =>
        BrasilCliExtension.Context.SignAsync(Request(settings, [.. context.Remaining.Raw]), cancellationToken);

    /// <summary>The run of <c>simplesign sign</c> for <paramref name="settings"/>: its arguments, and what the Brazilian options add.</summary>
    internal static CliSignRequest Request(Settings settings, IReadOnlyList<string> arguments) => new()
    {
        Arguments = arguments,
        Validate = settings.StandardError,
        Configure = (builder, sign, cancellation) => ConfigureAsync(builder, settings, sign, cancellation),
        ConfigureAppearance = (appearance, sign) => settings.Aea
            ? appearance.WithExtraLines([.. appearance.ExtraLines ?? [], sign.SignerName!, $"CPF: {AdvancedSignatureInfo.MaskCpf(settings.Cpf!)}"])
            : appearance,
        ShowsReason = settings.Aea,
        OwnsSignerData = settings.Aea,
    };

    private static async ValueTask<PadesSignerBuilder> ConfigureAsync(
        PadesSignerBuilder builder, Settings settings, CliSignOptions sign, CancellationToken cancellation)
    {
        // The advanced signature after the standard metadata: it adds its CMS attributes (the signer's manifest).
        if (settings.Aea)
        {
            builder = builder.WithAdvancedSignature(BrasilSignOptions.Build(
                signerName: sign.SignerName ?? string.Empty,
                cpf: settings.Cpf!,
                authMethod: sign.AuthMethod,
                email: sign.SignerEmail,
                institution: sign.Institution,
                institutionCnpj: settings.InstitutionCnpj,
                commitmentType: sign.Commitment,
                policyOid: sign.PolicyOid,
                policyUri: sign.PolicyUri));
        }

        // ICP-Brasil policy: version by the signer's root, PBAD.PAdES, and the level the policy needs.
        if (IcpBrasilCliOptions.ParsePolicy(settings.IcpPolicy) is { } policy)
        {
            IcpBrasilPolicyArtifacts? artifacts = null;
            if (policy == IcpBrasilPolicy.AdRa)
            {
                using var http = new HttpClient();
                artifacts = await IcpBrasilPolicyArtifacts.DownloadAsync(
                    http, builder.ResolveIcpBrasilPolicy(policy), cancellation).ConfigureAwait(false);
            }

            builder = builder.WithIcpBrasilPolicy(policy, new IcpBrasilPadesOptions
            {
                Timestamp = sign.Timestamp,
                Artifacts = artifacts,
            });
        }

        if (IcpBrasilCliOptions.ParseHealthDocument(settings.HealthDocument) is { } healthDocument)
        {
            builder = builder.WithHealthDocument(
                healthDocument,
                [.. (settings.Registrations ?? []).Select(r => IcpBrasilCliOptions.ParseRegistration(r)!)]);
        }

        return builder;
    }
}
