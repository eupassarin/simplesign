using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Brazil.IcpBrasil.Xades;
using SimpleSign.Cli.Extensibility;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Brazil.Cli;

/// <summary>The <c>--icp-policy</c> of <c>brasil cades sign</c> and <c>brasil xades sign</c>, and its checks.</summary>
internal sealed class IcpAdesPolicySettings : CommandSettings
{
    /// <summary>ICP-Brasil signature policy: ad-rb, ad-rt, ad-rv, ad-rc or ad-ra.</summary>
    [CommandOption("--icp-policy <POLICY>")]
    [Description("ICP-Brasil policy: ad-rb, ad-rt, ad-rv, ad-rc or ad-ra; the version follows the signer's root, and the policy sets the level and the validation data (all but ad-rb require --tsa, an ICP-Brasil ACT)")]
    public string? IcpPolicy { get; init; }

    /// <summary>The policy of <see cref="IcpPolicy"/>, or null.</summary>
    internal IcpBrasilPolicy? Policy => ParsePolicy(IcpPolicy);

    /// <inheritdoc />
    public override ValidationResult Validate() =>
        IcpPolicy is not null && Policy is null
            ? ValidationResult.Error("--icp-policy must be ad-rb, ad-rt, ad-rv, ad-rc or ad-ra.")
            : ValidationResult.Success();

    /// <summary>The error of the standard options next to <c>--icp-policy</c>, or null.</summary>
    internal string? StandardError(CliSignOptions sign)
    {
        if (Policy is not { } policy)
        {
            return null;
        }

        if (policy != IcpBrasilPolicy.AdRb && sign.Timestamp is null)
        {
            return $"--icp-policy {IcpPolicy!.ToLowerInvariant()} requires --tsa (an ICP-Brasil ACT).";
        }

        if (sign.LongTerm || sign.Archival)
        {
            return "--icp-policy sets the level and the validation data: use ad-rv, ad-rc or ad-ra instead of --level longterm/archive or --extended-form.";
        }

        return sign.PolicyOid is not null ? "--icp-policy and --policy-oid are mutually exclusive." : null;
    }

    /// <summary>Like <see cref="IcpBrasilCliOptions.ParsePolicy"/>, with AD-RV, which CAdES and XAdES have.</summary>
    private static IcpBrasilPolicy? ParsePolicy(string? value) =>
        value?.ToLowerInvariant() is "ad-rv" or "adrv" or "rv" ? IcpBrasilPolicy.AdRv : IcpBrasilCliOptions.ParsePolicy(value);
}

/// <summary>
/// <c>simplesign brasil cades sign</c>: the standard <c>simplesign cades sign</c>, every option of it, under an ICP-Brasil
/// CAdES policy (<c>--icp-policy</c>, DOC-ICP-15.03).
/// </summary>
[Description("Sign data with CAdES as 'simplesign cades sign' does (every option of it is accepted), under an ICP-Brasil policy")]
internal sealed class BrasilCadesSignCommand : AsyncCommand<IcpAdesPolicySettings>
{
    /// <inheritdoc />
    public override Task<int> ExecuteAsync(CommandContext context, IcpAdesPolicySettings settings, CancellationToken cancellationToken) =>
        BrasilCliExtension.Context.SignAsync(Request(settings, [.. context.Remaining.Raw]), cancellationToken);

    /// <summary>The run of <c>simplesign cades sign</c> for <paramref name="settings"/>.</summary>
    internal static CliSignRequest Request(IcpAdesPolicySettings settings, IReadOnlyList<string> arguments) => new()
    {
        Command = CliSignCommand.CadesSign,
        Arguments = arguments,
        Validate = settings.StandardError,
        ConfigureCades = (builder, sign, _) => ValueTask.FromResult(
            settings.Policy is { } policy ? builder.WithIcpBrasilPolicy(policy, sign.Timestamp) : builder),
    };
}

/// <summary>
/// <c>simplesign brasil xades sign</c>: the standard <c>simplesign xades sign</c>, every option of it, under an ICP-Brasil
/// XAdES policy (<c>--icp-policy</c>, the XML PAs of DOC-ICP-15.03).
/// </summary>
[Description("Sign an XML document with XAdES as 'simplesign xades sign' does (every option of it is accepted), under an ICP-Brasil policy")]
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
internal sealed class BrasilXadesSignCommand : AsyncCommand<IcpAdesPolicySettings>
{
    /// <inheritdoc />
    public override Task<int> ExecuteAsync(CommandContext context, IcpAdesPolicySettings settings, CancellationToken cancellationToken) =>
        BrasilCliExtension.Context.SignAsync(Request(settings, [.. context.Remaining.Raw]), cancellationToken);

    /// <summary>The run of <c>simplesign xades sign</c> for <paramref name="settings"/>.</summary>
    internal static CliSignRequest Request(IcpAdesPolicySettings settings, IReadOnlyList<string> arguments) => new()
    {
        Command = CliSignCommand.XadesSign,
        Arguments = arguments,
        Validate = settings.StandardError,
        ConfigureXades = (builder, sign, _) => ValueTask.FromResult(
            settings.Policy is { } policy ? builder.WithIcpBrasilPolicy(policy, sign.Timestamp) : builder),
    };
}
