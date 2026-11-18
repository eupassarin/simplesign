using System.Net;
using System.Text;
using System.Text.Json;
using Shouldly;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>The client against an imitation of the checker's API, as its web page uses it.</summary>
[Trait("Category", "Unit")]
public sealed class EtsiCheckerClientTests
{
    private static readonly EtsiSample Sample = EtsiCorpus.Get("cades-b-b");

    private static readonly byte[] Report =
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "cades-b-b.xmlrawoutput.xml"));

    [Fact]
    public async Task CheckAsync_SignsInThenUploads_ReadsTheReport()
    {
        var checker = new FakeChecker();
        var client = Client(checker);

        var upload = await client.CheckAsync(Sample, [1, 2, 3]);

        checker.SignIns.ShouldBe(1);
        checker.LastUpload.ShouldNotBeNull();
        checker.LastUpload.Authorization.ShouldBe("Bearer token-1");
        checker.LastUpload.Fields.ShouldBe(new Dictionary<string, string>
        {
            ["selectedSpec"] = "EN31912201v010101",
            ["sig"] = "cades",
        });
        checker.LastUpload.FileName.ShouldBe("cades-b-b.p7m");
        checker.LastUpload.File.ShouldBe([1, 2, 3]);
        upload.SessionId.ShouldBe("session-1");
        upload.Signatures.ShouldBe(["CAdES-signature-1"]);
        upload.Documents.Keys.ShouldContain("CAdES-signature-1/docs/fullreport.html");
        upload.Report.Successes.ShouldBe(7);
        upload.Report.Findings.ShouldBeEmpty();
    }

    [Fact]
    public async Task CheckAsync_TokenNoLongerValid_SignsInAgainAndRetries()
    {
        var checker = new FakeChecker();
        var client = Client(checker);
        await client.CheckAsync(Sample, [1]);
        checker.ValidToken = "token-2";

        var upload = await client.CheckAsync(Sample, [1]);

        checker.SignIns.ShouldBe(2);
        checker.LastUpload!.Authorization.ShouldBe("Bearer token-2");
        upload.Report.Successes.ShouldBe(7);
    }

    [Fact]
    public async Task CheckAsync_SignInRefused_ThrowsWithoutThePassword()
    {
        var checker = new FakeChecker { RefuseSignIn = true };

        var error = await Should.ThrowAsync<HttpRequestException>(() => Client(checker).CheckAsync(Sample, [1]));

        error.Message.ShouldContain("user@example.test");
        error.Message.ShouldNotContain("s3cret");
    }

    [Fact]
    public async Task CheckAsync_UploadRefused_ThrowsWithTheChecker_sAnswer()
    {
        var checker = new FakeChecker { UploadStatus = HttpStatusCode.UnprocessableEntity };

        var error = await Should.ThrowAsync<HttpRequestException>(() => Client(checker).CheckAsync(Sample, [1]));

        error.Message.ShouldContain("cades-b-b.p7m (422)");
        error.Message.ShouldContain("not a CMS");
    }

    private static EtsiCheckerClient Client(FakeChecker checker) =>
        new(new HttpClient(new MockHttpHandler(checker.HandleAsync)) { BaseAddress = new Uri("https://checker.example.test/") },
            "user@example.test", "s3cret")
        { Pause = TimeSpan.Zero };

    private sealed record Upload(string? Authorization, Dictionary<string, string> Fields, string? FileName, byte[] File);

    private static async Task<Upload> ReadUploadAsync(string? authorization, MultipartFormDataContent form)
    {
        var fields = new Dictionary<string, string>();
        string? fileName = null;
        byte[] file = [];
        foreach (var part in form)
        {
            var disposition = part.Headers.ContentDisposition!;
            if (disposition.Name == "file")
            {
                fileName = disposition.FileName;
                file = await part.ReadAsByteArrayAsync();
            }
            else
            {
                fields[disposition.Name!] = await part.ReadAsStringAsync();
            }
        }

        return new Upload(authorization, fields, fileName, file);
    }

    private sealed class FakeChecker
    {
        public string ValidToken { get; set; } = "token-1";

        public bool RefuseSignIn { get; init; }

        public HttpStatusCode UploadStatus { get; init; } = HttpStatusCode.OK;

        public int SignIns { get; private set; }

        public Upload? LastUpload { get; private set; }

        public async Task<HttpResponseMessage> HandleAsync(HttpRequestMessage request)
        {
            string body = request.Content is null ? "" : await request.Content.ReadAsStringAsync();
            switch (request.RequestUri!.AbsolutePath)
            {
                case "/api/auth/login":
                    body.ShouldBe("username=user%40example.test&password=s3cret");
                    if (RefuseSignIn)
                    {
                        return Json(HttpStatusCode.Unauthorized, """{"detail":"Incorrect username or password"}""");
                    }

                    SignIns++;
                    return Json(HttpStatusCode.OK, $$"""{"access_token":"{{ValidToken}}","token_type":"Bearer"}""");

                case "/api/sig/uploadfile":
                    string? authorization = request.Headers.Authorization?.ToString();
                    if (authorization != $"Bearer {ValidToken}")
                    {
                        return Json(HttpStatusCode.Unauthorized, """{"detail":"Not authorised."}""");
                    }

                    LastUpload = await ReadUploadAsync(authorization, (MultipartFormDataContent)request.Content!);
                    if (UploadStatus != HttpStatusCode.OK)
                    {
                        return Json(UploadStatus, """{"detail":"not a CMS"}""");
                    }

                    var answer = new Dictionary<string, object>
                    {
                        ["filename"] = "cades-b-b.p7m",
                        ["sig"] = "cades",
                        ["sessionid"] = "session-1",
                        ["siglist"] = new[] { "CAdES-signature-1" },
                        ["result"] = new Dictionary<string, string>
                        {
                            ["CAdES-signature-1/docs/xmlrawoutput.xml"] = Convert.ToBase64String(Report),
                            ["CAdES-signature-1/docs/fullreport.html"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("<html/>")),
                        },
                    };
                    return Json(HttpStatusCode.OK, JsonSerializer.Serialize(answer));

                default:
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
            new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }
}
