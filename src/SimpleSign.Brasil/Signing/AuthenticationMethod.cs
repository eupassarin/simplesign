namespace SimpleSign.Brasil.Signing;

/// <summary>
/// Authentication method used to identify the signer
/// in an Advanced Electronic Signature (Lei 14.063/2020).
/// </summary>
public enum AuthenticationMethod
{
    /// <summary>Institutional login (SSO, Active Directory, etc.).</summary>
    InstitutionalLogin,

    /// <summary>Digital certificate (ICP-Brasil or other).</summary>
    DigitalCertificate,

    /// <summary>Gov.br (Brazilian federal digital identity platform).</summary>
    GovBr,

    /// <summary>Facial biometrics.</summary>
    FacialBiometrics,

    /// <summary>OTP token (one-time password).</summary>
    TokenOtp,

    /// <summary>Username and password.</summary>
    UsernamePassword,
}

/// <summary>
/// Extension methods for <see cref="AuthenticationMethod"/>.
/// </summary>
public static class AuthenticationMethodExtensions
{
    /// <summary>
    /// Returns a human-readable label for the authentication method.
    /// </summary>
    public static string ToDisplayString(this AuthenticationMethod method) => method switch
    {
        AuthenticationMethod.InstitutionalLogin => "Institutional login",
        AuthenticationMethod.DigitalCertificate => "Digital certificate",
        AuthenticationMethod.GovBr => "Gov.br",
        AuthenticationMethod.FacialBiometrics => "Facial biometrics",
        AuthenticationMethod.TokenOtp => "Token OTP",
        AuthenticationMethod.UsernamePassword => "Username and password",
        _ => method.ToString(),
    };
}
