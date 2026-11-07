using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// Rules every signature format shares (PAdES, CAdES, XAdES): TSA choice, hash and RSA padding
/// against the credential, and the signer certificate itself.
/// </summary>
internal static class SharedRules
{
    /// <summary>Which TSA providers can be chosen in the current environment.</summary>
    public static void TsaProviders(bool sandbox, Action<string, OptionState> set)
    {
        foreach (var provider in Enum.GetValues<TsaProvider>())
        {
            bool sandboxProvider = provider is TsaProvider.Sandbox or TsaProvider.SandboxAuthenticated;
            set($"tsa.{provider}", sandbox && !sandboxProvider && provider != TsaProvider.Custom
                    ? OptionState.Off(L.T("The sandbox is offline. Switch to Real to use public TSAs."))
                : !sandbox && sandboxProvider ? OptionState.Off(L.T("Sandbox services exist only in Sandbox mode."))
                : OptionState.Shown);
        }

        set("tsa.clientCertificate", sandbox
            ? new OptionState(true, Note: L.T("The sandbox TSA does not check TLS client certificates; the option is still passed to TimestampOptions.ClientCertificate."))
            : OptionState.Shown);
    }

    /// <summary>Checks one TSA choice (provider allowed, URL, authentication).</summary>
    public static void CheckTsa(TimestampChoice tsa, string label, IReadOnlyDictionary<string, OptionState> state, Action<string, string> error, bool sandbox, string step)
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
            else if (sandbox && !uri.Host.EndsWith(SandboxPki.Host, StringComparison.OrdinalIgnoreCase))
            {
                error(step, L.T("{0}: the sandbox is offline; only *.{1} URLs answer.", label, SandboxPki.Host));
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

        if (tsa.Provider == TsaProvider.SandboxAuthenticated && tsa.Auth != TsaAuth.Basic)
        {
            error(step, L.T("{0}: the authenticated sandbox TSA needs Basic authentication ({1} / {2}).", label, SandboxPki.TsaUser, SandboxPki.TsaPassword));
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
    /// The signer certificate: chosen, currently valid, with nonRepudiation; and what the signing policy refuses
    /// (null: no signing policy applies).
    /// </summary>
    public static void Signer(CredentialFacts? credential, Action<string, string> error, Action<string, string> warn, string step,
        SigningPolicyChoice? policy = SigningPolicyChoice.Default)
    {
        if (credential is null)
        {
            error(step, L.T("Choose a signer (certificate)."));
            return;
        }

        if (credential.IsExpired)
        {
            error(step, L.T("The certificate has expired: the library refuses to sign with it (SigningException)."));
        }

        if (credential.IsNotYetValid)
        {
            error(step, L.T("The certificate is not valid yet: the library refuses to sign with it (SigningException)."));
        }

        if (policy is SigningPolicyChoice.Default or SigningPolicyChoice.Strict)
        {
            if (!credential.HasSigningKeyUsage)
            {
                error(step, L.T("The certificate allows neither digitalSignature nor nonRepudiation: the signing policy refuses it (KeyUsageNotPermitted). Choose the Minimal policy to try it anyway."));
            }

            if (credential.KeyAlgorithm == "RSA" && credential.KeySize is > 0 and < 2048)
            {
                error(step, L.T("The RSA key has {0} bits: the signing policy requires at least 2048 (KeyTooWeak). Choose the Minimal policy to try it anyway.", credential.KeySize));
            }
        }

        if (!credential.HasNonRepudiation)
        {
            warn(step, L.T("The certificate lacks the nonRepudiation key usage: some validation policies warn about it."));
        }
    }
}
