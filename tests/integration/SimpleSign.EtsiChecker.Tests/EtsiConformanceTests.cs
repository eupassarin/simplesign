using Shouldly;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>
/// Every sample of <see cref="EtsiCorpus"/> checked by the ETSI Signatures Conformance Checker against the baseline
/// profile of its format (EN 319 142-1, EN 319 122-1, EN 319 132-1). The checker looks at the structure: the
/// attributes and properties each level requires or forbids, their encoding, the imprints of the time-stamps; not
/// at trust, so the synthetic PKI does. A failure fails the test unless <c>known-issues.json</c> accepts it, and an
/// accepted failure that no longer happens fails it too, so the list stays true. What the checker said is kept in
/// <c>docs/conformance/etsi-checker</c> (<see cref="EtsiCheckerSession"/>). Needs an account
/// (<see cref="EtsiChecker.Require"/>), so it runs on a developer's machine, not in CI.
/// </summary>
[Trait("Category", "EtsiChecker")]
public sealed class EtsiConformanceTests(OfflinePki pki, EtsiCheckerSession session, ITestOutputHelper output)
    : IClassFixture<OfflinePki>, IClassFixture<EtsiCheckerSession>
{
    [SkippableTheory]
    [MemberData(nameof(EtsiCorpus.Ids), MemberType = typeof(EtsiCorpus))]
    public async Task Check_EverySample_ConformsToItsBaselineProfile(string id)
    {
        var (user, password) = EtsiChecker.Require();
        var sample = EtsiCorpus.Get(id);
        byte[] signed = await sample.Sign(pki);

        var upload = await session.Client(user, password).CheckAsync(sample, signed);
        var report = upload.Report;
        var issues = KnownIssue.All.Where(k => k.Sample == "*" || k.Sample == id).ToList();
        var known = report.Failures.Where(f => issues.Any(k => k.Matches(id, f))).ToList();
        await session.RecordAsync(sample, signed, upload, known);
        output.WriteLine($"{id} ({upload.SessionId}): {report.Summary}");

        report.Signatures.ShouldNotBeEmpty("the checker found no signature");
        report.Failures.Except(known).ShouldBeEmpty(report.Summary);
        issues.Where(k => k.Sample == id && !report.Failures.Any(f => k.Matches(id, f)))
            .Select(k => $"{k.Check} ({k.Link}) no longer fails: remove it from known-issues.json")
            .ShouldBeEmpty();
    }
}
