using SimpleSign.Brazil.Signing;
using SimpleSign.Core.Signing;

namespace SimpleSign.Brazil.Cli;

/// <summary>Parses the options of an advanced electronic signature (AEA, Lei 14.063) of <c>brasil sign</c>.</summary>
internal static class BrasilSignOptions
{
    internal static AdvancedSignatureInfo Build(string signerName, string cpf, string? authMethod,
        string? email, string? institution, string? institutionCnpj,
        string? commitmentType, string? policyOid, string? policyUri)
    {
        return new AdvancedSignatureInfo
        {
            SignerName = signerName,
            Cpf = cpf,
            AuthMethod = ParseAuthMethod(authMethod),
            Email = email,
            InstitutionName = institution,
            InstitutionCnpj = institutionCnpj,
            CommitmentType = ParseCommitmentType(commitmentType),
            PolicyOid = policyOid,
            PolicyUri = policyUri,
        };
    }

    /// <summary>Whether <paramref name="value"/> is one of the authentication methods of <c>--auth-method</c>.</summary>
    internal static bool IsAuthMethod(string value) => value.ToLowerInvariant()
        is "digital-certificate" or "digital_certificate"
        or "gov-br" or "gov_br" or "govbr"
        or "institutional-login" or "institutional_login"
        or "facial-biometrics" or "facial_biometrics"
        or "token-otp" or "token_otp"
        or "username-password" or "username_password";

    internal static AuthenticationMethod ParseAuthMethod(string? value) => value?.ToLowerInvariant() switch
    {
        "institutional-login" or "institutional_login" => AuthenticationMethod.InstitutionalLogin,
        "digital-certificate" or "digital_certificate" => AuthenticationMethod.DigitalCertificate,
        "gov-br" or "gov_br" or "govbr" => AuthenticationMethod.GovBr,
        "facial-biometrics" or "facial_biometrics" => AuthenticationMethod.FacialBiometrics,
        "token-otp" or "token_otp" => AuthenticationMethod.TokenOtp,
        "username-password" or "username_password" => AuthenticationMethod.UsernamePassword,
        _ => AuthenticationMethod.DigitalCertificate,
    };

    internal static CommitmentType ParseCommitmentType(string? value) => value?.ToLowerInvariant() switch
    {
        "approval" => CommitmentType.ProofOfApproval,
        "origin" => CommitmentType.ProofOfOrigin,
        _ => CommitmentType.ProofOfApproval,
    };
}
