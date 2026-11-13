using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Policies;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// Rules every signature format shares (PAdES, CAdES, XAdES): TSA choice, hash and RSA padding
/// against the credential, and the signer certificate itself.
/// </summary>
internal static class SharedRules
{
    /// <summary>Which TSA providers can be chosen: the Sandbox's TSAs only while a Sandbox is connected.</summary>
    public static void TsaProviders(bool sandboxConnected, Action<string, OptionState> set)
    {
        foreach (var provider in Enum.GetValues<TsaProvider>())
        {
            set($"tsa.{provider}", !sandboxConnected && IsSandboxTsa(provider)
                ? OptionState.Off(L.T("Connect a SimpleSign Sandbox in Environment to use its TSAs."))
                : OptionState.Shown);
        }

        set("tsa.clientCertificate", OptionState.Shown);
    }

    /// <summary>Whether a provider is one of the connected Sandbox's TSAs.</summary>
    public static bool IsSandboxTsa(TsaProvider provider) =>
        provider is TsaProvider.Sandbox or TsaProvider.SandboxAuthenticated or TsaProvider.SandboxUntrusted or TsaProvider.SandboxRevoked or TsaProvider.SandboxExpired or TsaProvider.SandboxWrongName
            or TsaProvider.SandboxShortLived or TsaProvider.SandboxIofe or TsaProvider.SandboxNonQualified;

    /// <summary>Checks one TSA choice (provider allowed, URL, authentication).</summary>
    public static void CheckTsa(TimestampChoice tsa, string label, IReadOnlyDictionary<string, OptionState> state, Action<string, string> error, string step)
    {
        if (state[$"tsa.{tsa.Provider}"].Disabled is { } reason)
        {
            error(step, $"{label}: {reason}");
        }

        if (tsa.Provider == TsaProvider.Custom)
        {
            if (!Uri.TryCreate(tsa.Url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https" or "tcp"))
            {
                error(step, L.T("{0}: enter an absolute http://, https:// or tcp:// URL.", label));
            }
        }

        if (tsa.Auth == TsaAuth.Basic && (string.IsNullOrEmpty(tsa.User) || tsa.Password is null))
        {
            error(step, L.T("{0}: Basic authentication needs a user and a password.", label));
        }

        if (tsa.Auth == TsaAuth.Bearer && string.IsNullOrWhiteSpace(tsa.Token))
        {
            error(step, L.T("{0}: Bearer authentication needs a token.", label));
        }
    }

    /// <summary>Hash and RSA padding against the credential. Returns the padding that will be used.</summary>
    public static RsaPadding Crypto(HashChoice hash, RsaPadding padding, CredentialFacts? credential, Dictionary<string, OptionState> state, Action<string, string> error, string step)
    {
        IReadOnlyList<HashChoice> hashes = credential?.Hashes ?? Enum.GetValues<HashChoice>();
        foreach (var h in Enum.GetValues<HashChoice>())
        {
            state[$"hash.{h}"] = hashes.Contains(h) ? OptionState.Shown
                : credential is null ? OptionState.Shown
                : OptionState.Off(h is HashChoice.Sha3_256 or HashChoice.Sha3_384 or HashChoice.Sha3_512 && credential.CanSignHashLocally
                    ? L.T("SHA-3 is not available in this runtime (needs OpenSSL 1.1.1+ or Windows 11).")
                    : L.T("{0} signers accept SHA-256, SHA-384 and SHA-512 only.", credential.Kind));
        }

        if (credential is not null && !hashes.Contains(hash))
        {
            error(step, state[$"hash.{hash}"].Disabled ?? L.T("This hash is not available."));
        }

        bool isRsa = credential is null || credential.KeyAlgorithm == "RSA";
        state["padding"] = isRsa ? OptionState.Shown : new OptionState(false, Note: L.T("ECDSA keys sign with ECDSA; RSA padding does not apply."));
        foreach (var p in Enum.GetValues<RsaPadding>())
        {
            state[$"padding.{p}"] = credential is null || credential.Paddings.Contains(p) ? OptionState.Shown
                : OptionState.Off(credential.Kind switch
                {
                    CredentialKind.Csc => L.T("This CSC credential does not list the algorithm in its key/algo."),
                    _ => L.T("Not supported by this key."),
                });
        }

        bool sha3 = hash is HashChoice.Sha3_256 or HashChoice.Sha3_384 or HashChoice.Sha3_512;
        if (sha3 && state["padding.Pss"].Disabled is null)
        {
            state["padding.Pss"] = OptionState.Off(L.T("The library supports RSASSA-PSS with SHA-256, SHA-384 and SHA-512 only (salt = hash length)."));
        }

        if (isRsa && sha3 && padding == RsaPadding.Pss && credential?.Paddings.Contains(RsaPadding.Pss) == true)
        {
            error(step, L.T("RSASSA-PSS cannot be combined with a SHA-3 digest: choose SHA-2 or PKCS#1 v1.5."));
        }

        if (!isRsa)
        {
            return RsaPadding.Pkcs1;
        }

        return credential is not null && !credential.Paddings.Contains(padding) ? credential.Paddings.FirstOrDefault() : padding;
    }

    /// <summary>
    /// The signer certificate: chosen, and what the signing policy says about it (FAIL: an error, WARN: a warning).
    /// The certificate is checked with <see cref="SigningPolicy.Evaluate"/>; without the certificate itself, only
    /// with the facts read from it.
    /// </summary>
    public static void Signer(CredentialFacts? credential, Action<string, string> error, Action<string, string> warn, string step,
        SigningPolicyInput? policy = null)
    {
        policy ??= SigningPolicyInput.Default;
        if (policy.Error is { } policyError)
        {
            error(step, L.T("The signing policy cannot be read: {0}", policyError));
        }

        if (credential is null)
        {
            error(step, L.T("Choose a signer (certificate)."));
            return;
        }

        if (Certificate(credential) is { } certificate)
        {
            using (certificate)
            {
                foreach (var finding in policy.Policy.Evaluate(certificate, DateTimeOffset.UtcNow))
                {
                    string text = L.T("The signing policy \"{0}\" ({1}: {2}) says: {3}", policy.Policy.Name, finding.Constraint, finding.Level.ToString().ToUpperInvariant(), finding.Message);
                    switch (finding.Level)
                    {
                        case ConstraintLevel.Fail:
                            error(step, L.T("{0} The library refuses to sign (SigningException, {1}). Upload a signing policy that relaxes the constraint to try it anyway.", text, finding.Reason));
                            break;
                        case ConstraintLevel.Warn:
                            warn(step, text);
                            break;
                    }
                }
            }
        }
        else
        {
            FromFacts(credential, policy.Policy, error, step);
        }

        if (!credential.HasNonRepudiation)
        {
            warn(step, L.T("The certificate lacks the nonRepudiation key usage: some validation policies warn about it."));
        }
    }

    /// <summary>The checks of the policy that the facts of a credential answer, when its certificate is not at hand.</summary>
    private static void FromFacts(CredentialFacts credential, SigningPolicy policy, Action<string, string> error, string step)
    {
        if (Fails(policy, "SigningCertificate/NotExpired"))
        {
            if (credential.IsExpired)
            {
                error(step, L.T("The certificate has expired: the library refuses to sign with it (SigningException)."));
            }

            if (credential.IsNotYetValid)
            {
                error(step, L.T("The certificate is not valid yet: the library refuses to sign with it (SigningException)."));
            }
        }

        if (Fails(policy, "SigningCertificate/KeyUsage") && !credential.HasSigningKeyUsage)
        {
            error(step, L.T("The certificate allows neither digitalSignature nor nonRepudiation: the signing policy refuses it (KeyUsageNotPermitted). Upload a signing policy that relaxes the constraint to try it anyway."));
        }

        if (Fails(policy, "Cryptographic") && credential.KeyAlgorithm == "RSA" && credential.KeySize is > 0 and < 2048)
        {
            error(step, L.T("The RSA key has {0} bits: the signing policy requires at least 2048 (KeyTooWeak). Upload a signing policy that relaxes the constraint to try it anyway.", credential.KeySize));
        }
    }

    private static bool Fails(SigningPolicy policy, string path) => policy.Find(path)?.Level == ConstraintLevel.Fail;

    private static X509Certificate2? Certificate(CredentialFacts credential)
    {
        if (string.IsNullOrEmpty(credential.CertificateBase64))
        {
            return null;
        }

        try
        {
            return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(credential.CertificateBase64));
        }
        catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }
}
