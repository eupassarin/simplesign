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

    public async Task InitializeAsync()
    {
        Documents.AddSamples(await SampleDocuments.CreateAsync(Sandbox));
        ValidationSamples = await SimpleSign.TestBench.Validation.InvalidSamples.CreateAsync(Sandbox, Documents);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    public void Dispose()
    {
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
