using SimpleSign.Core.Http;

namespace SimpleSign.TestBench.Sandbox;

/// <summary>Sandbox (offline, simulated) or Real (your certificates, real TSAs and providers).</summary>
public enum EnvironmentMode
{
    Sandbox,
    Real,
}

/// <summary>Everything the sandbox simulates, created once per process.</summary>
internal sealed class SandboxEnvironment : IDisposable
{
    public SandboxEnvironment()
    {
        Pki = new SandboxPki();
        Psc = new SandboxPsc(Pki);
        Csc = new SandboxCsc(Pki);
        Network = new SandboxNetwork(Pki, Psc, Csc);
    }

    public SandboxPki Pki { get; }

    public SandboxPsc Psc { get; }

    public SandboxCsc Csc { get; }

    public SandboxNetwork Network { get; }

    /// <summary>The HTTP provider for a mode: the sandbox network, or the real internet.</summary>
    public IHttpClientProvider HttpFor(EnvironmentMode mode) =>
        mode == EnvironmentMode.Sandbox ? Network : DefaultHttpClientProvider.Instance;

    public void Dispose()
    {
        Network.Dispose();
        Psc.Dispose();
        Csc.Dispose();
        Pki.Dispose();
    }
}
