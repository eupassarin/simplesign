using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// The TestBench services shared by the tests of a collection, connected to a running SimpleSign
/// Sandbox (<c>SIMPLESIGN_SANDBOX_URL</c>, default http://localhost:5300). Without one, the tests
/// that need it are skipped (CI starts one first).
/// </summary>
public sealed class TestBenchFixture : IAsyncLifetime, IDisposable
{
    /// <summary>Where the tests look for the Sandbox.</summary>
    public static Uri SandboxUrl { get; } = new(Environment.GetEnvironmentVariable("SIMPLESIGN_SANDBOX_URL") is { Length: > 0 } url ? url : "http://localhost:5300/");

    internal SandboxEnvironment Sandbox { get; } = new();

    /// <summary>Why the Sandbox could not be reached; null when connected.</summary>
    public string? SandboxProblem { get; private set; }

    /// <summary>
    /// Skips the calling test when no Sandbox is connected; fails it instead when
    /// <c>SIMPLESIGN_REQUIRE_SANDBOX</c> is "true" (CI starts one, so a missing Sandbox is an error there).
    /// </summary>
    public void RequireSandbox()
    {
        if (SandboxProblem is null)
        {
            return;
        }

        string message = $"No SimpleSign Sandbox at {SandboxUrl} ({SandboxProblem}). Start one: dotnet run --project src/Apps/SimpleSign.Sandbox";
        if (string.Equals(Environment.GetEnvironmentVariable("SIMPLESIGN_REQUIRE_SANDBOX"), "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(message);
        }

        Skip.If(true, message);
    }

    internal DocumentStore Documents { get; } = new();

    internal CredentialStore Credentials { get; } = new();

    internal SigningRunner Runner => new(Sandbox, Documents, Credentials);

    internal CredentialFactory Factory => new(Sandbox, Documents);

    /// <summary>The validation samples: signed with the Sandbox's signers, so the caller is skipped without one.</summary>
    internal IReadOnlyList<SimpleSign.TestBench.Validation.ValidationSample> ValidationSamples
    {
        get
        {
            RequireSandbox();
            return _validationSamples;
        }
    }

    private IReadOnlyList<SimpleSign.TestBench.Validation.ValidationSample> _validationSamples = [];

    internal SimpleSign.TestBench.Validation.ValidationService Validation => new(Sandbox, Documents);

    /// <summary>The Cades samples; the caller is skipped without a Sandbox (the signed ones need it).</summary>
    internal IReadOnlyList<SimpleSign.TestBench.Cades.CadesSample> CadesSamples
    {
        get
        {
            RequireSandbox();
            return _cadesSamples;
        }
    }

    private IReadOnlyList<SimpleSign.TestBench.Cades.CadesSample> _cadesSamples = [];

    internal SimpleSign.TestBench.Cades.CadesRunner Cades => new(Sandbox, Documents, Credentials, Validation);

    /// <summary>The Xml samples; the caller is skipped without a Sandbox (the signed ones need it).</summary>
    internal IReadOnlyList<SimpleSign.TestBench.Xml.XmlSample> XmlSamples
    {
        get
        {
            RequireSandbox();
            return _xmlSamples;
        }
    }

    private IReadOnlyList<SimpleSign.TestBench.Xml.XmlSample> _xmlSamples = [];

    internal SimpleSign.TestBench.Xml.XmlRunner Xml => new(Sandbox, Documents, Credentials, Validation);

    private readonly List<IDisposable> _owned = [];

    /// <summary>A run service; <paramref name="dss"/> sets where the DSS cross-validation service is.</summary>
    internal SimpleSign.TestBench.Runs.RunService Runs(SimpleSign.TestBench.CrossValidation.DssSettings? dss = null)
    {
        var client = new SimpleSign.TestBench.CrossValidation.DssClient(Documents);
        _owned.Add(client);
        if (dss is not null)
        {
            client.Settings = dss;
        }

        return new(Runner, Cades, Xml, client, Validation, Documents);
    }

    public async Task InitializeAsync()
    {
        try
        {
            await Sandbox.ConnectAsync(SandboxUrl);
            await Sandbox.ResetAsync();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException or System.Text.Json.JsonException)
        {
            SandboxProblem = ex.Message;
        }

        Documents.AddSamples(await SampleDocuments.CreateAsync());
        _validationSamples = await SimpleSign.TestBench.Validation.InvalidSamples.CreateAsync(Sandbox, Documents);
        _cadesSamples = await SimpleSign.TestBench.Cades.CadesSamples.CreateAsync(Sandbox, Documents);
        _xmlSamples = await SimpleSign.TestBench.Xml.XmlSamples.CreateAsync(Sandbox, Documents);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    public void Dispose()
    {
        foreach (var owned in _owned)
        {
            owned.Dispose();
        }

        Credentials.Dispose();
        Sandbox.Dispose();
    }

    internal string Sandboxed(string signerId = "rsa-2048")
    {
        RequireSandbox();
        return Credentials.Add(Factory.OpenSandbox(new SandboxCredentialRequest(signerId))).Id;
    }

    internal SigningOptions Options(string sample = "contract", string signer = "rsa-2048") => new()
    {
        DocumentId = DocumentStore.SampleKey(sample),
        CredentialId = Sandboxed(signer),
    };
}

[CollectionDefinition(Name)]
public sealed class TestBenchCollection : ICollectionFixture<TestBenchFixture>
{
    public const string Name = "TestBench sandbox";
}
