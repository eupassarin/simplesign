using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Diagnostics;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Diagnostics;

/// <summary>
/// The traces and metrics of <see cref="SimpleSignTelemetry"/>. Listeners are process-wide, so each test looks only at
/// what it made itself (a format or host of its own).
/// </summary>
[Trait("Category", "Unit")]
public sealed class TelemetryTests : IDisposable
{
    private readonly MeterListener _meters = new();
    private readonly ActivityListener _activities;
    private readonly ConcurrentQueue<(string Instrument, double Value, Dictionary<string, object?> Tags)> _measurements = new();
    private readonly ConcurrentQueue<Activity> _stopped = new();

    public TelemetryTests()
    {
        _meters.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == SimpleSignTelemetry.Name)
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _meters.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Record(instrument, value, tags));
        _meters.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Record(instrument, value, tags));
        _meters.Start();
        _activities = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SimpleSignTelemetry.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = _stopped.Enqueue,
        };
        ActivitySource.AddActivityListener(_activities);
    }

    public void Dispose()
    {
        _meters.Dispose();
        _activities.Dispose();
    }

    [Fact]
    public async Task Signing_Made_CountsFormatLevelsAndSuccessWithoutCertificateData()
    {
        string format = Unique("sign");

        await SignatureAudit.RunAsync<byte[]>(null, () => Event(format), () => Task.FromResult(new byte[] { 1 }),
            r => (r, AdesBaselineLevel.Timestamped), CancellationToken.None);

        var count = Single(SimpleSignTelemetry.Instruments.SigningOperations, SimpleSignTelemetry.Tags.Format, format);
        count.Tags[SimpleSignTelemetry.Tags.Outcome].ShouldBe(SimpleSignTelemetry.Outcomes.Success);
        count.Tags[SimpleSignTelemetry.Tags.RequestedLevel].ShouldBe("Basic");
        count.Tags[SimpleSignTelemetry.Tags.AchievedLevel].ShouldBe("Timestamped");
        Single(SimpleSignTelemetry.Instruments.SigningDuration, SimpleSignTelemetry.Tags.Format, format).Value.ShouldBeGreaterThanOrEqualTo(0);
        var activity = Activity(SimpleSignTelemetry.Activities.Sign, format);
        activity.TagObjects.Select(t => t.Value?.ToString()).ShouldNotContain(v => v != null && v.Contains("Secret Holder", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Signing_RefusedByPolicy_CountsRefusedWithReason()
    {
        string format = Unique("refused");

        await Should.ThrowAsync<SigningException>(() => SignatureAudit.RunAsync<byte[]>(null, () => Event(format),
            () => throw new SigningException("no", SigningErrorReason.KeyTooWeak), r => (r, AdesBaselineLevel.Basic), CancellationToken.None));

        var count = Single(SimpleSignTelemetry.Instruments.SigningOperations, SimpleSignTelemetry.Tags.Format, format);
        count.Tags[SimpleSignTelemetry.Tags.Outcome].ShouldBe(SimpleSignTelemetry.Outcomes.Refused);
        count.Tags[SimpleSignTelemetry.Tags.Reason].ShouldBe(nameof(SigningErrorReason.KeyTooWeak));
    }

    [Fact]
    public async Task Crl_FromCache_CountsCacheHitAndHostOnly()
    {
        using var pki = new SyntheticPki();
        string host = Unique("crl") + ".example";
        string url = $"http://{host}/ca.crl?token=secret";
        var cache = new InMemoryRevocationCache(TimeSpan.FromMinutes(5));
        cache.Set(url, pki.BuildLeafCrl(), DateTimeOffset.UtcNow.AddMinutes(5));
        using var http = MockHttpHandler.Failing();

        await new CrlClient(http) { Cache = cache }.CheckCrlAsync(pki.Leaf, pki.IntermediateCa, url, CancellationToken.None);

        var count = Single(SimpleSignTelemetry.Instruments.CrlFetches, SimpleSignTelemetry.Tags.ServerAddress, host);
        count.Tags[SimpleSignTelemetry.Tags.CacheHit].ShouldBe(true);
        count.Tags[SimpleSignTelemetry.Tags.Outcome].ShouldBe(SimpleSignTelemetry.Outcomes.Success);
        count.Tags.Values.OfType<string>().Any(v => v.Contains("token", StringComparison.Ordinal)).ShouldBeFalse();
    }

    [Fact]
    public async Task Timestamp_TsaFails_CountsErrorWithHost()
    {
        string host = Unique("tsa") + ".example";
        using var http = MockHttpHandler.Failing();
        var client = new TimestampClient(http, $"https://{host}/tsr");

        await Should.ThrowAsync<Exception>(() => client.GetTimestampForHashAsync(SHA256.HashData("x"u8), HashAlgorithmName.SHA256, CancellationToken.None));

        var count = Single(SimpleSignTelemetry.Instruments.TimestampRequests, SimpleSignTelemetry.Tags.ServerAddress, host);
        count.Tags[SimpleSignTelemetry.Tags.Outcome].ShouldBe(SimpleSignTelemetry.Outcomes.Error);
        Activity(SimpleSignTelemetry.Activities.Timestamp, host, SimpleSignTelemetry.Tags.ServerAddress).Status.ShouldBe(ActivityStatusCode.Error);
    }

    [Fact]
    public async Task MeasureValidation_NestedCalls_CountsEachSignatureOnce()
    {
        string format = Unique("validate");

        await Telemetry.MeasureValidationAsync(format,
            () => Task.FromResult(Telemetry.MeasureValidation(format, () => new[] { "Valid", "Indeterminate" }, r => r)), r => r);

        var counts = All(SimpleSignTelemetry.Instruments.Validations, SimpleSignTelemetry.Tags.Format, format);
        counts.Select(c => c.Tags[SimpleSignTelemetry.Tags.Indication]).ShouldBe(["Valid", "Indeterminate"], ignoreOrder: true);
        Single(SimpleSignTelemetry.Instruments.ValidationDuration, SimpleSignTelemetry.Tags.Format, format)
            .Tags[SimpleSignTelemetry.Tags.Indication].ShouldBe("Mixed");
    }

    [Fact]
    public void Constants_SourceAndMeter_AreNamedSimpleSign()
    {
        Telemetry.Source.Name.ShouldBe("SimpleSign");
        Telemetry.Meter.Name.ShouldBe("SimpleSign");
    }

    [Fact]
    public void Scope_Inactive_CompleteDoesNothing() =>
        Should.NotThrow(() => default(Telemetry.Scope).Complete(SimpleSignTelemetry.Outcomes.Success));

    private static string Unique(string prefix) => $"{prefix}-{Guid.NewGuid():N}";

    private static SignatureAuditEvent Event(string format) => new()
    {
        Time = DateTimeOffset.UtcNow,
        Format = format,
        RequestedLevel = AdesBaselineLevel.Basic,
        Signed = false,
        CertificateSubject = "CN=Secret Holder",
        PolicyName = SigningPolicy.Default.Name,
    };

    private void Record<T>(Instrument instrument, T value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        where T : struct
    {
        var copy = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var tag in tags)
        {
            copy[tag.Key] = tag.Value;
        }

        _measurements.Enqueue((instrument.Name, Convert.ToDouble(value, System.Globalization.CultureInfo.InvariantCulture), copy));
    }

    private List<(string Instrument, double Value, Dictionary<string, object?> Tags)> All(string instrument, string tag, string value) =>
        [.. _measurements.Where(m => m.Instrument == instrument && m.Tags.TryGetValue(tag, out var v) && Equals(v, value))];

    private (string Instrument, double Value, Dictionary<string, object?> Tags) Single(string instrument, string tag, string value) =>
        All(instrument, tag, value).ShouldHaveSingleItem();

    private Activity Activity(string name, string value, string tag = SimpleSignTelemetry.Tags.Format) =>
        _stopped.Single(a => a.OperationName == name && Equals(a.GetTagItem(tag), value));
}
