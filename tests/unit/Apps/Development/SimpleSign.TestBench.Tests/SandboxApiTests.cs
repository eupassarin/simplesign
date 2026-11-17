using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Shouldly;
using SimpleSign.TestBench.Endpoints;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// The link to the Sandbox: its root, handed out for an external validator (DSS) or a reader (Adobe) to trust, and its
/// admin API passed through for the TestBench's Sandbox control.
/// </summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SandboxApiTests(TestBenchFixture fixture)
{
    [SkippableFact]
    public void RootCertificate_Connected_IsTheRootInDer()
    {
        fixture.RequireSandbox();

        byte[] der = SandboxApi.RootCertificate(fixture.Sandbox).ShouldNotBeNull();

        using var root = X509CertificateLoader.LoadCertificate(der);
        root.Thumbprint.ShouldBe(fixture.Sandbox.Connection.Root.Thumbprint);
        SandboxApi.RootFileName.ShouldEndWith(".cer");
    }

    [Fact]
    public void RootCertificate_NotConnected_IsNull()
    {
        using var sandbox = new SandboxEnvironment(Path.Combine(Path.GetTempPath(), $"simplesign-sandbox-{Guid.NewGuid():N}.json"));

        SandboxApi.RootCertificate(sandbox).ShouldBeNull();
    }

    [Fact]
    public async Task Forward_NotConnected_Is409()
    {
        using var sandbox = new SandboxEnvironment(Path.Combine(Path.GetTempPath(), $"simplesign-sandbox-{Guid.NewGuid():N}.json"));
        var context = Context("GET");

        await SandboxApi.Forward(context, "pki", sandbox);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        Body(context).ShouldContain("error");
    }

    [SkippableFact]
    public async Task Forward_Pki_IsTheSandboxsAnswer()
    {
        fixture.RequireSandbox();
        var context = Context("GET");

        await SandboxApi.Forward(context, "pki", fixture.Sandbox);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
        context.Response.ContentType.ShouldNotBeNull().ShouldStartWith("application/json");
        using var json = JsonDocument.Parse(Body(context));
        json.RootElement.GetProperty("certificates").GetArrayLength().ShouldBeGreaterThan(0);
    }

    [SkippableFact]
    public async Task Forward_PatchFaults_ChangesTheSandboxAndAnswersTheFaults()
    {
        fixture.RequireSandbox();
        try
        {
            var context = Context("PATCH", """{"tsa":"Down"}""");

            await SandboxApi.Forward(context, "faults", fixture.Sandbox);

            context.Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
            using var json = JsonDocument.Parse(Body(context));
            json.RootElement.GetProperty("tsa").GetString().ShouldBe("Down");
        }
        finally
        {
            await SandboxApi.Forward(Context("DELETE"), "faults", fixture.Sandbox);
        }
    }

    [SkippableFact]
    public async Task Forward_Pfx_KeepsTheFileNameAndType()
    {
        fixture.RequireSandbox();
        string id = fixture.Sandbox.Connection.Signers[0].Id;
        var context = Context("GET");

        await SandboxApi.Forward(context, $"certificates/{id}/pfx", fixture.Sandbox);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
        context.Response.ContentType.ShouldBe("application/x-pkcs12");
        context.Response.Headers.ContentDisposition.ToString().ShouldContain($"{id}.pfx");
    }

    [SkippableFact]
    public async Task Forward_UnknownRoute_IsTheSandboxs404()
    {
        fixture.RequireSandbox();
        var context = Context("GET");

        await SandboxApi.Forward(context, "nothing-here", fixture.Sandbox);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status404NotFound);
    }

    private static DefaultHttpContext Context(string method, string? json = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        if (json is not null)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            context.Request.Body = new MemoryStream(bytes);
            context.Request.ContentLength = bytes.Length;
            context.Request.ContentType = "application/json";
        }

        context.Response.Body = new MemoryStream();
        return context;
    }

    private static string Body(HttpContext context)
    {
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, leaveOpen: true);
        return reader.ReadToEnd();
    }
}
