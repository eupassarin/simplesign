using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;

namespace SimpleSign.TestHelpers;

/// <summary>
/// A chain validation provider that takes every signer, records the context it was asked with and answers what it is
/// told: trusted or not, with the data of a trust framework (region TEST, A1, a CPF, one metadata entry).
/// </summary>
public sealed class RecordingChainValidationProvider(bool trusted = true) : IChainValidationProvider
{
    /// <summary>The context of the last <see cref="ValidateAsync(ChainValidationContext, CancellationToken)"/>.</summary>
    public ChainValidationContext? Asked { get; private set; }

    /// <inheritdoc />
    public string RegionCode => "TEST";

    /// <inheritdoc />
    public bool CanValidate(X509Certificate2 certificate) => true;

    /// <inheritdoc />
    public Task<ChainValidationResult> ValidateAsync(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain = null) =>
        ValidateAsync(new ChainValidationContext { Certificate = certificate, Certificates = chain ?? [] }, CancellationToken.None);

    /// <inheritdoc />
    public Task<ChainValidationResult> ValidateAsync(ChainValidationContext context, CancellationToken cancellationToken)
    {
        Asked = context;
        return Task.FromResult(new ChainValidationResult
        {
            IsTrusted = trusted,
            RegionCode = RegionCode,
            PolicyLevel = "A1",
            SignerId = "12345678909",
            SignerIdType = "CPF",
            Metadata = new Dictionary<string, string> { ["TEST.Key"] = "value" },
            Errors = trusted ? [] : ["not a test certificate"],
        });
    }
}
