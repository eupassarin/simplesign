using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>One sandbox (PKI, TSA, samples) shared by the tests of a collection: key generation is slow.</summary>
public sealed class TestBenchFixture : IAsyncLifetime, IDisposable
{
    internal SandboxEnvironment Sandbox { get; } = new();

    internal DocumentStore Documents { get; } = new();

    internal CredentialStore Credentials { get; } = new();

    internal SigningRunner Runner => new(Sandbox, Documents, Credentials);

    internal CredentialFactory Factory => new(Sandbox, Documents);

    internal IReadOnlyList<SimpleSign.TestBench.Validation.ValidationSample> ValidationSamples { get; private set; } = [];

    internal SimpleSign.TestBench.Validation.ValidationService Validation => new(Sandbox, Documents);

    internal IReadOnlyList<SimpleSign.TestBench.Cades.CadesSample> CadesSamples { get; private set; } = [];

    internal SimpleSign.TestBench.Cades.CadesRunner Cades => new(Sandbox, Documents, Credentials, Validation);

    internal IReadOnlyList<SimpleSign.TestBench.Xml.XmlSample> XmlSamples { get; private set; } = [];

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

        return new(Runner, Cades, Xml, client);
    }

    public async Task InitializeAsync()
    {
        Documents.AddSamples(await SampleDocuments.CreateAsync(Sandbox));
        ValidationSamples = await SimpleSign.TestBench.Validation.InvalidSamples.CreateAsync(Sandbox, Documents);
        CadesSamples = await SimpleSign.TestBench.Cades.CadesSamples.CreateAsync(Sandbox, Documents);
        XmlSamples = await SimpleSign.TestBench.Xml.XmlSamples.CreateAsync(Sandbox, Documents);
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

    internal string Sandboxed(string signerId = "rsa-2048") =>
        Credentials.Add(Factory.OpenSandbox(new SandboxCredentialRequest(signerId))).Id;

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
