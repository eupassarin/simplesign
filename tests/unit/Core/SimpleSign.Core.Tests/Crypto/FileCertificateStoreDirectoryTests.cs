using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

/// <summary>
/// Tests for the directory-based constructor and edge-case lookups in
/// <see cref="FileCertificateStore"/>. Complements <see cref="CertificateStoreTests"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class FileCertificateStoreDirectoryTests : IDisposable
{
    private readonly string _tempDir;

    public FileCertificateStoreDirectoryTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"simplesign-store-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch
        {
            // Best-effort cleanup
        }
    }

    // ── Directory constructor ────────────────────────────────────────────────

    [Fact(DisplayName = "Directory constructor loads all valid PFX files matching the pattern")]
    public void DirectoryCtor_LoadsAllMatchingPfx()
    {
        WritePfx("alice.pfx", "CN=Alice", "pw");
        WritePfx("bob.pfx", "CN=Bob", "pw");
        WritePfx("charlie.pfx", "CN=Charlie", "pw");

        using var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");

        store.ListAll().Count().ShouldBe(3);
    }

    [Fact(DisplayName = "Directory constructor honours the search pattern (only .p12 files loaded)")]
    public void DirectoryCtor_SearchPatternFilters()
    {
        WritePfx("alice.pfx", "CN=Alice", "pw");
        WritePfx("bob.p12", "CN=Bob", "pw");

        using var store = new FileCertificateStore(_tempDir, "pw", "*.p12");

        store.ListAll().Count().ShouldBe(1);
        store.ListAll()[0].Subject.ShouldContain("Bob");
    }

    [Fact(DisplayName = "Directory constructor with empty directory returns empty store")]
    public void DirectoryCtor_EmptyDir_EmptyStore()
    {
        using var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");
        store.ListAll().ShouldBeEmpty();
    }

    [Fact(DisplayName = "Directory constructor skips files with wrong password silently")]
    public void DirectoryCtor_WrongPasswordFile_IsSkipped()
    {
        WritePfx("good.pfx", "CN=Good", "correct");
        WritePfx("bad.pfx", "CN=Bad", "different-password");

        using var store = new FileCertificateStore(_tempDir, "correct", "*.pfx");

        // Only the file with the matching password loads
        store.ListAll().Count().ShouldBe(1);
        store.ListAll()[0].Subject.ShouldContain("Good");
    }

    [Fact(DisplayName = "Directory constructor skips corrupt files silently")]
    public void DirectoryCtor_CorruptFile_IsSkipped()
    {
        WritePfx("good.pfx", "CN=Good", "pw");
        File.WriteAllBytes(Path.Combine(_tempDir, "corrupt.pfx"), [0xFF, 0xFE, 0xFD]);

        using var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");

        store.ListAll().Count().ShouldBe(1);
    }

    // ── Lookup negative paths ────────────────────────────────────────────────

    [Fact(DisplayName = "FindByThumbprint returns null when no match")]
    public void FindByThumbprint_NoMatch_ReturnsNull()
    {
        WritePfx("alice.pfx", "CN=Alice", "pw");
        using var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");

        store.FindByThumbprint("not-a-real-thumbprint").ShouldBeNull();
    }

    [Fact(DisplayName = "FindByThumbprint is case-insensitive")]
    public void FindByThumbprint_CaseInsensitive_ReturnsMatch()
    {
        var path = WritePfx("alice.pfx", "CN=Alice", "pw");
        using var loadedCert = CertificateLoader.LoadPkcs12FromFile(path, "pw");
        using var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");

        var found = store.FindByThumbprint(loadedCert.Thumbprint.ToLowerInvariant());
        found.ShouldNotBeNull();
    }

    [Fact(DisplayName = "FindBySubject returns empty list when no match")]
    public void FindBySubject_NoMatch_ReturnsEmpty()
    {
        WritePfx("alice.pfx", "CN=Alice", "pw");
        using var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");

        store.FindBySubject("Bob").ShouldBeEmpty();
    }

    [Fact(DisplayName = "FindBySubject returns multiple matches (substring match)")]
    public void FindBySubject_PartialMatch_ReturnsAll()
    {
        WritePfx("alice.pfx", "CN=Alice Smith", "pw");
        WritePfx("bob.pfx", "CN=Bob Smith", "pw");
        WritePfx("eve.pfx", "CN=Eve Jones", "pw");
        using var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");

        store.FindBySubject("Smith").Count().ShouldBe(2);
    }

    // ── Disposal ─────────────────────────────────────────────────────────────

    [Fact(DisplayName = "Dispose called twice does not throw")]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        WritePfx("alice.pfx", "CN=Alice", "pw");
        var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");

        store.Dispose();
        Action act = () => store.Dispose();
        Should.NotThrow(act);
    }

    [Fact(DisplayName = "ListAll after Dispose returns empty list")]
    public void ListAll_AfterDispose_IsEmpty()
    {
        WritePfx("alice.pfx", "CN=Alice", "pw");
        var store = new FileCertificateStore(_tempDir, "pw", "*.pfx");
        store.Dispose();

        store.ListAll().ShouldBeEmpty();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a self-signed cert in memory and exports directly to PFX without round-tripping
    /// through <c>CertificateLoader</c>. This avoids the macOS keychain "contents cannot be
    /// retrieved" error you get if you try to re-export a cert that was previously imported.
    /// </summary>
    private string WritePfx(string filename, string subject, string password)
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var path = Path.Combine(_tempDir, filename);
        File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx, password));
        return path;
    }
}
