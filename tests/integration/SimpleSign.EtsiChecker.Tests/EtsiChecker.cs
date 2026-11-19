using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>
/// Where the conformance tests reach the ETSI Signatures Conformance Checker
/// (<see href="https://signatures-conformance-checker.etsi.org"/>) and where they keep what it says. The checker needs an
/// account: <c>SIMPLESIGN_ETSI_USER</c> and <c>SIMPLESIGN_ETSI_PASSWORD</c>. Without them the tests that upload are
/// skipped, or fail when <c>SIMPLESIGN_REQUIRE_ETSI_CHECKER</c> is "true".
/// </summary>
public static class EtsiChecker
{
    /// <summary>The checker's address; <c>SIMPLESIGN_ETSI_URL</c> replaces it.</summary>
    public static Uri BaseAddress =>
        new(Environment.GetEnvironmentVariable("SIMPLESIGN_ETSI_URL") is { Length: > 0 } url ? url : "https://signatures-conformance-checker.etsi.org/");

    /// <summary>The largest file the checker accepts (20 MB).</summary>
    public const int MaxUploadBytes = 20 * 1024 * 1024;

    /// <summary>The account the tests sign in with; null when it is not set.</summary>
    public static (string User, string Password)? Credentials =>
        Environment.GetEnvironmentVariable("SIMPLESIGN_ETSI_USER") is { Length: > 0 } user
        && Environment.GetEnvironmentVariable("SIMPLESIGN_ETSI_PASSWORD") is { Length: > 0 } password
            ? (user, password)
            : null;

    /// <summary>Where the corpus is written for an upload by hand (<c>SIMPLESIGN_ETSI_CORPUS</c>); null when not set.</summary>
    public static string? CorpusDirectory =>
        Environment.GetEnvironmentVariable("SIMPLESIGN_ETSI_CORPUS") is { Length: > 0 } path ? path : null;

    /// <summary>
    /// Where the checker's reports are kept: <c>SIMPLESIGN_ETSI_EVIDENCE</c>, or <c>docs/conformance/etsi-checker</c> in
    /// the repository, where they are committed.
    /// </summary>
    public static string EvidenceDirectory =>
        Environment.GetEnvironmentVariable("SIMPLESIGN_ETSI_EVIDENCE") is { Length: > 0 } path
            ? path
            : RepositoryPaths.Get("docs", "conformance", "etsi-checker");

    /// <summary>
    /// Where what is not committed goes: the signed samples and the checker's whole zip
    /// (<c>SIMPLESIGN_ETSI_ARTIFACTS</c>, or <c>etsi-checker</c> next to the test assembly).
    /// </summary>
    public static string ArtifactsDirectory =>
        Environment.GetEnvironmentVariable("SIMPLESIGN_ETSI_ARTIFACTS") is { Length: > 0 } path
            ? path
            : Path.Combine(AppContext.BaseDirectory, "etsi-checker");

    /// <summary>Skips the calling test without an account; fails it instead when <c>SIMPLESIGN_REQUIRE_ETSI_CHECKER</c> is "true".</summary>
    /// <returns>The account.</returns>
    public static (string User, string Password) Require()
    {
        if (Credentials is { } credentials)
        {
            return credentials;
        }

        const string problem = "The ETSI checker needs an account: set SIMPLESIGN_ETSI_USER and SIMPLESIGN_ETSI_PASSWORD.";
        if (string.Equals(Environment.GetEnvironmentVariable("SIMPLESIGN_REQUIRE_ETSI_CHECKER"), "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(problem);
        }

        Skip.If(true, problem);
        return default;
    }
}
