using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.VisualTree;
using Shouldly;
using SimpleSign.Agent.Services;
using SimpleSign.Agent.Views.Pages;

namespace SimpleSign.Agent.Tests;

/// <summary>
/// <see cref="CertificateEntry"/> reads its certificate when it is built, not when a row is drawn: the window redraws
/// a certificate row on a log entry or a language change, which can happen after the lister released the certificate,
/// and every member of <c>X509Certificate2</c> revalidates the handle and throws once it is disposed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CertificateEntryTests
{
    [Fact]
    public void Properties_AfterTheCertificateIsDisposed_StillAnswer()
    {
        var certificate = Fixtures.RsaCertificate("CN=Maria Fernanda Oliveira, O=ICP-Brasil, C=BR");
        var entry = new CertificateEntry(CertificateSourceKind.Store, certificate);
        string holder = entry.Holder;

        certificate.Dispose();

        entry.Holder.ShouldBe(holder);
        entry.Issuer.ShouldNotBeNull();
        entry.Validity.ShouldNotBeNullOrEmpty();
        entry.IsExpired.ShouldBeFalse();
        entry.DaysLeft.ShouldBeGreaterThan(0);
        entry.Display.ShouldContain(holder);
        _ = entry.MaskedDocument;
        _ = entry.Document;
        _ = entry.PolicyIssue;
        _ = entry.IsIcpBrasil;
    }

    [AvaloniaFact]
    public void CertificateRow_AfterTheCertificateIsDisposed_StillDraws()
    {
        var certificate = Fixtures.RsaCertificate("CN=Empresa Exemplo Ltda, C=BR");
        var entry = new CertificateEntry(CertificateSourceKind.Store, certificate);
        certificate.Dispose();

        var row = OverviewPage.CertificateRow(entry, ["ICP-Brasil"]);

        row.GetVisualDescendants().OfType<TextBlock>().ShouldNotBeEmpty();
    }
}
