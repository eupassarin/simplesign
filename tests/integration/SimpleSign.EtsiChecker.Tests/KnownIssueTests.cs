using Shouldly;
using Xunit;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary><c>known-issues.json</c> read, and in step with the corpus.</summary>
[Trait("Category", "Unit")]
public sealed class KnownIssueTests
{
    [Fact]
    public void All_EveryIssue_IsAboutASampleOfTheCorpus()
    {
        var ids = EtsiCorpus.Samples.Select(s => s.Id).ToHashSet();

        KnownIssue.All.ShouldAllBe(k => k.Sample == "*" || ids.Contains(k.Sample));
    }

    [Fact]
    public void All_EverySampleNotBaseline_HasTheFailureItExpects()
    {
        var notBaseline = EtsiCorpus.Samples.Where(s => !s.IsBaseline).Select(s => s.Id).ToList();

        notBaseline.ShouldNotBeEmpty();
        notBaseline.ShouldAllBe(id => KnownIssue.All.Any(k => k.Sample == id));
    }

    [Fact]
    public void Matches_SameSampleCheckAndText_IsTheIssue()
    {
        var issue = new KnownIssue("pades-b-t-adbe", "CheckIfValueIsOneOfDefined", "'adbe.pkcs7.detached'", "why", "link");
        var finding = new EtsiFinding("PAdES-signature-1", EtsiCheckOutcome.Failure, "CheckFailure", "CheckIfValueIsOneOfDefined",
            "SubFilter", "Found value: 'adbe.pkcs7.detached''. Allowed values: ETSI.CAdES.detached");

        issue.Matches("pades-b-t-adbe", finding).ShouldBeTrue();
        issue.Matches("pades-b-t", finding).ShouldBeFalse();
        (issue with { MessageContains = "PBAD" }).Matches("pades-b-t-adbe", finding).ShouldBeFalse();
        (issue with { Sample = "*" }).Matches("pades-b-t", finding).ShouldBeTrue();
    }
}
