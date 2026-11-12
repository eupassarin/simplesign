using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace SimpleSign.Core.Diagnostics;

/// <summary>The activity source and instruments of <see cref="SimpleSignTelemetry"/>.</summary>
internal static class Telemetry
{
    private static readonly string? s_version = typeof(Telemetry).Assembly.GetName().Version?.ToString(3);

    internal static readonly ActivitySource Source = new(SimpleSignTelemetry.Name, s_version);

    internal static readonly Meter Meter = new(SimpleSignTelemetry.Name, s_version);

    internal static readonly Instrument Signing = new(SimpleSignTelemetry.Activities.Sign, ActivityKind.Internal,
        Meter.CreateCounter<long>(SimpleSignTelemetry.Instruments.SigningOperations, "{operation}", "Signing operations, made or refused."),
        Meter.CreateHistogram<double>(SimpleSignTelemetry.Instruments.SigningDuration, "s", "Duration of signing operations."));

    internal static readonly Instrument Timestamp = new(SimpleSignTelemetry.Activities.Timestamp, ActivityKind.Client,
        Meter.CreateCounter<long>(SimpleSignTelemetry.Instruments.TimestampRequests, "{request}", "Requests to timestamping authorities."),
        Meter.CreateHistogram<double>(SimpleSignTelemetry.Instruments.TimestampDuration, "s", "Duration of timestamp requests."));

    internal static readonly Instrument Ocsp = new(SimpleSignTelemetry.Activities.Ocsp, ActivityKind.Client,
        Meter.CreateCounter<long>(SimpleSignTelemetry.Instruments.OcspRequests, "{request}", "Requests to OCSP responders."),
        Meter.CreateHistogram<double>(SimpleSignTelemetry.Instruments.OcspDuration, "s", "Duration of OCSP requests."));

    internal static readonly Instrument Crl = new(SimpleSignTelemetry.Activities.Crl, ActivityKind.Client,
        Meter.CreateCounter<long>(SimpleSignTelemetry.Instruments.CrlFetches, "{fetch}", "CRLs fetched, from a cache or the network."),
        Meter.CreateHistogram<double>(SimpleSignTelemetry.Instruments.CrlDuration, "s", "Duration of CRL fetches."));

    internal static readonly Instrument TrustedList = new(SimpleSignTelemetry.Activities.TrustedListLoad, ActivityKind.Internal,
        Meter.CreateCounter<long>(SimpleSignTelemetry.Instruments.TrustedListLoads, "{list}", "Trusted lists read and checked."),
        Meter.CreateHistogram<double>(SimpleSignTelemetry.Instruments.TrustedListDuration, "s", "Duration of trusted list reading."));

    internal static readonly Instrument Validation = new(SimpleSignTelemetry.Activities.Validate, ActivityKind.Internal,
        Meter.CreateCounter<long>(SimpleSignTelemetry.Instruments.Validations, "{signature}", "Signatures validated, by indication."),
        Meter.CreateHistogram<double>(SimpleSignTelemetry.Instruments.ValidationDuration, "s", "Duration of the validation of a document."));

    /// <summary>Set while a validation is measured, so the overloads that call each other count it once.</summary>
    private static readonly AsyncLocal<bool> s_inValidation = new();

    private static readonly object s_true = true;
    private static readonly object s_false = false;

    /// <summary>A boxed bool that allocates nothing.</summary>
    internal static object Boxed(bool value) => value ? s_true : s_false;

    /// <summary>The host of <paramref name="url"/>, or null; never its path or query.</summary>
    internal static string? HostOf(string? url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : null;

    /// <summary>
    /// Measures a validation of <paramref name="format"/>: one count per signature by indication, one duration for the
    /// document. Nothing is measured when nobody listens or a validation is already measured (overloads that call
    /// each other count once).
    /// </summary>
    /// <param name="format">The signature format.</param>
    /// <param name="validate">The validation.</param>
    /// <param name="indications">The indication of each signature of the result.</param>
    internal static async Task<T> MeasureValidationAsync<T>(string format, Func<Task<T>> validate, Func<T, IEnumerable<string>> indications)
    {
        if (!Validation.IsEnabled || s_inValidation.Value)
        {
            return await validate().ConfigureAwait(false);
        }

        s_inValidation.Value = true;
        var scope = Validation.Start();
        try
        {
            var result = await validate().ConfigureAwait(false);
            CompleteValidation(scope, format, [.. indications(result)]);
            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            scope.Complete(SimpleSignTelemetry.Outcomes.Error, count: false, [new(SimpleSignTelemetry.Tags.Format, format)]);
            throw;
        }
        finally
        {
            s_inValidation.Value = false;
        }
    }

    /// <summary>The synchronous form of <see cref="MeasureValidationAsync"/>.</summary>
    internal static T MeasureValidation<T>(string format, Func<T> validate, Func<T, IEnumerable<string>> indications)
    {
        if (!Validation.IsEnabled || s_inValidation.Value)
        {
            return validate();
        }

        s_inValidation.Value = true;
        var scope = Validation.Start();
        try
        {
            var result = validate();
            CompleteValidation(scope, format, [.. indications(result)]);
            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            scope.Complete(SimpleSignTelemetry.Outcomes.Error, count: false, [new(SimpleSignTelemetry.Tags.Format, format)]);
            throw;
        }
        finally
        {
            s_inValidation.Value = false;
        }
    }

    private static void CompleteValidation(Scope scope, string format, List<string> indications)
    {
        foreach (string indication in indications)
        {
            Validation.Counter.Add(1, new TagList
            {
                { SimpleSignTelemetry.Tags.Format, format },
                { SimpleSignTelemetry.Tags.Indication, indication },
            });
        }

        string summary = indications.Count == 0 ? "None" : indications.Distinct(StringComparer.Ordinal).Count() == 1 ? indications[0] : "Mixed";
        scope.Complete(SimpleSignTelemetry.Outcomes.Success, count: false,
            [new(SimpleSignTelemetry.Tags.Format, format), new(SimpleSignTelemetry.Tags.Indication, summary)]);
    }

    /// <summary>An activity source name and its two instruments.</summary>
    internal sealed class Instrument(string activityName, ActivityKind kind, Counter<long> counter, Histogram<double> duration)
    {
        public Counter<long> Counter { get; } = counter;

        public Histogram<double> Duration { get; } = duration;

        /// <summary>Whether anything listens to the activity or the instruments.</summary>
        public bool IsEnabled => Counter.Enabled || Duration.Enabled || Source.HasListeners();

        /// <summary>Starts an operation; inactive (nothing measured, nothing allocated) when nobody listens.</summary>
        public Scope Start() => IsEnabled ? new Scope(this, Source.StartActivity(activityName, kind), Stopwatch.GetTimestamp()) : default;
    }

    /// <summary>One measured operation: its activity and its start.</summary>
    internal readonly struct Scope(Instrument? instrument, Activity? activity, long started)
    {
        /// <summary>Whether the operation is measured (build tags only then).</summary>
        public bool IsActive => instrument is not null;

        /// <summary>Records the outcome and ends the activity.</summary>
        /// <param name="outcome">One of <see cref="SimpleSignTelemetry.Outcomes"/>.</param>
        /// <param name="tags">More tags (no personal data); null values are left out.</param>
        public void Complete(string outcome, params ReadOnlySpan<KeyValuePair<string, object?>> tags) => Complete(outcome, count: true, tags);

        /// <summary>Records the outcome (and counts the operation when <paramref name="count"/>) and ends the activity.</summary>
        public void Complete(string outcome, bool count, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            if (instrument is null)
            {
                return;
            }

            var list = new TagList { { SimpleSignTelemetry.Tags.Outcome, outcome } };
            foreach (var tag in tags)
            {
                if (tag.Value is not null)
                {
                    list.Add(tag);
                }
            }

            if (count)
            {
                instrument.Counter.Add(1, list);
            }

            instrument.Duration.Record(Stopwatch.GetElapsedTime(started).TotalSeconds, list);
            if (activity is not null)
            {
                foreach (var tag in list)
                {
                    activity.SetTag(tag.Key, tag.Value);
                }

                if (outcome == SimpleSignTelemetry.Outcomes.Error)
                {
                    activity.SetStatus(ActivityStatusCode.Error);
                }

                activity.Dispose();
            }
        }
    }
}
