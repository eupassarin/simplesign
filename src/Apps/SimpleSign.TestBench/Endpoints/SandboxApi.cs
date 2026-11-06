using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Endpoints;

/// <summary>A certificate of the sandbox PKI.</summary>
public sealed record SandboxCertificate(
    string Id,
    string Role,
    string Title,
    string? Description,
    string Subject,
    string Issuer,
    string SerialNumber,
    string NotBefore,
    string NotAfter,
    string Key,
    string Thumbprint,
    string? Problem,
    bool IsUsable,
    bool RevokedNow);

/// <summary>The sandbox as the Environment panel shows it: the PKI, the faults switched on, and where the root is kept.</summary>
public sealed record SandboxState(
    SandboxCertificate Root,
    SandboxCertificate Intermediate,
    SandboxCertificate Tsa,
    IReadOnlyList<SandboxCertificate> Signers,
    SandboxFaults Faults,
    bool FaultsActive,
    string RootCrlUrl,
    string IntermediateCrlUrl,
    string TsaUrl);

/// <summary>The sandbox as a lab: look at its PKI, download its certificates and CRLs, and switch failures on.</summary>
internal static class SandboxApi
{
    public static void Map(RouteGroupBuilder api)
    {
        var sandbox = api.MapGroup("/sandbox");
        sandbox.MapGet("/state", (SandboxEnvironment env) => State(env));
        sandbox.MapPut("/faults", (SandboxFaults faults, SandboxEnvironment env) =>
        {
            env.Network.Faults = faults;
            return State(env);
        });
        sandbox.MapPost("/signers/{id}/revoke", (string id, SandboxEnvironment env) =>
        {
            if (env.Pki.Signers.All(s => s.Id != id))
            {
                return Results.NotFound();
            }

            env.Pki.Revoke(id);
            return Results.Ok(State(env));
        });
        sandbox.MapPost("/reset", (SandboxEnvironment env) =>
        {
            env.Network.Faults = new SandboxFaults();
            env.Pki.RestoreRevocations();
            return State(env);
        });
        sandbox.MapGet("/certificates/{id}", (string id, SandboxEnvironment env) =>
            Find(env, id) is { } certificate
                ? Results.File(certificate.RawData, "application/pkix-cert", $"sandbox-{id}.cer")
                : Results.NotFound());
        sandbox.MapGet("/crls/{name}", (string name, SandboxEnvironment env) => name switch
        {
            "root.crl" => Results.File(env.Pki.RootCrl, "application/pkix-crl", "sandbox-root.crl"),
            "intermediate.crl" => Results.File(env.Pki.IntermediateCrl, "application/pkix-crl", "sandbox-intermediate.crl"),
            _ => Results.NotFound(),
        });
    }

    internal static SandboxState State(SandboxEnvironment env)
    {
        var pki = env.Pki;
        var revoked = pki.RevokedNow;
        var faults = env.Network.Faults;
        return new SandboxState(
            View("root", "root", L.T("Root CA"), null, pki.Root, null, true, false),
            View("intermediate", "intermediate", L.T("Intermediate CA"), null, pki.Intermediate, null, true, false),
            View("tsa", "tsa", L.T("Time-stamping authority"), null, pki.Tsa, null, true, false),
            [.. pki.Signers.Select(s => View(s.Id, "signer", L.T(s.Title), L.T(s.Description), s.Certificate, s.Problem is null ? null : L.T(s.Problem), s.IsUsable, revoked.Contains(s.Id)))],
            faults,
            faults.Any || revoked.Count > 0,
            SandboxPki.RootCrlUri.AbsoluteUri,
            SandboxPki.IntermediateCrlUri.AbsoluteUri,
            SandboxPki.TsaUri.AbsoluteUri);
    }

    private static X509Certificate2? Find(SandboxEnvironment env, string id) => id switch
    {
        "root" => env.Pki.Root,
        "intermediate" => env.Pki.Intermediate,
        "tsa" => env.Pki.Tsa,
        _ => env.Pki.Signers.FirstOrDefault(s => s.Id == id)?.Certificate,
    };

    private static SandboxCertificate View(string id, string role, string title, string? description, X509Certificate2 c, string? problem, bool usable, bool revokedNow)
    {
        string key = c.GetRSAPublicKey() is { } rsa ? $"RSA {rsa.KeySize}" : c.GetECDsaPublicKey() is { } ec ? $"ECDSA {ec.KeySize}" : c.PublicKey.Oid.FriendlyName ?? "?";
        return new SandboxCertificate(id, role, title, description, c.Subject, c.Issuer, c.SerialNumber,
            c.NotBefore.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), c.NotAfter.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            key, c.Thumbprint, problem, usable, revokedNow);
    }
}
