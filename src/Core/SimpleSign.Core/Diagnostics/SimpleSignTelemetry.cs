namespace SimpleSign.Core.Diagnostics;

/// <summary>
/// The names of SimpleSign's traces and metrics, for OpenTelemetry or any <c>ActivityListener</c>/<c>MeterListener</c>:
/// one <see cref="System.Diagnostics.ActivitySource"/> and one <see cref="System.Diagnostics.Metrics.Meter"/>, both
/// named <see cref="Name"/>.
/// </summary>
/// <remarks>
/// Nothing is measured until something listens: with no listener, activities are not created and instruments are not
/// recorded. Tags carry formats, levels, outcomes, reasons, indications and server host names only — never payloads,
/// certificate subjects, serial numbers, full URLs or other personal data.
/// <code>
/// builder.Services.AddOpenTelemetry()
///     .WithTracing(t =&gt; t.AddSource(SimpleSignTelemetry.Name))
///     .WithMetrics(m =&gt; m.AddMeter(SimpleSignTelemetry.Name));
/// </code>
/// </remarks>
public static class SimpleSignTelemetry
{
    /// <summary>The name of the activity source and of the meter.</summary>
    public const string Name = "SimpleSign";

    /// <summary>The names of the activities.</summary>
    public static class Activities
    {
        /// <summary>A signature made (or refused) by a PAdES, CAdES or XAdES signer, one-call or deferred.</summary>
        public const string Sign = "SimpleSign.Sign";

        /// <summary>A request to a timestamping authority.</summary>
        public const string Timestamp = "SimpleSign.Timestamp";

        /// <summary>A request to an OCSP responder.</summary>
        public const string Ocsp = "SimpleSign.Ocsp";

        /// <summary>A CRL fetched (from a cache, HTTP or LDAP).</summary>
        public const string Crl = "SimpleSign.Crl";

        /// <summary>An ETSI trusted list read and checked.</summary>
        public const string TrustedListLoad = "SimpleSign.TrustedList.Load";

        /// <summary>A validation of the signatures of a document.</summary>
        public const string Validate = "SimpleSign.Validate";
    }

    /// <summary>The names of the instruments. Counters count operations; histograms measure durations in seconds.</summary>
    public static class Instruments
    {
        /// <summary>Counter of signing operations (tags: format, requested and achieved level, outcome, reason).</summary>
        public const string SigningOperations = "simplesign.signing.operations";

        /// <summary>Histogram of signing durations, in seconds.</summary>
        public const string SigningDuration = "simplesign.signing.duration";

        /// <summary>Counter of timestamp requests (tags: server address, outcome).</summary>
        public const string TimestampRequests = "simplesign.timestamp.requests";

        /// <summary>Histogram of timestamp request durations, in seconds.</summary>
        public const string TimestampDuration = "simplesign.timestamp.duration";

        /// <summary>Counter of OCSP requests (tags: server address, outcome).</summary>
        public const string OcspRequests = "simplesign.ocsp.requests";

        /// <summary>Histogram of OCSP request durations, in seconds.</summary>
        public const string OcspDuration = "simplesign.ocsp.duration";

        /// <summary>Counter of CRL fetches (tags: server address, outcome, cache hit).</summary>
        public const string CrlFetches = "simplesign.crl.fetches";

        /// <summary>Histogram of CRL fetch durations, in seconds.</summary>
        public const string CrlDuration = "simplesign.crl.duration";

        /// <summary>Counter of trusted lists read (tags: outcome).</summary>
        public const string TrustedListLoads = "simplesign.trusted_list.loads";

        /// <summary>Histogram of trusted list reading durations, in seconds.</summary>
        public const string TrustedListDuration = "simplesign.trusted_list.duration";

        /// <summary>Counter of signatures validated (tags: format, indication).</summary>
        public const string Validations = "simplesign.validations";

        /// <summary>Histogram of validation durations (one document, all its signatures), in seconds.</summary>
        public const string ValidationDuration = "simplesign.validation.duration";
    }

    /// <summary>The names of the tags.</summary>
    public static class Tags
    {
        /// <summary>The signature format: <c>PAdES</c>, <c>CAdES</c> or <c>XAdES</c>.</summary>
        public const string Format = "simplesign.format";

        /// <summary>The baseline level requested (B, T, LT, LTA as <c>AdesBaselineLevel</c> names).</summary>
        public const string RequestedLevel = "simplesign.level.requested";

        /// <summary>The baseline level achieved.</summary>
        public const string AchievedLevel = "simplesign.level.achieved";

        /// <summary>The outcome: one of <see cref="Outcomes"/>.</summary>
        public const string Outcome = "simplesign.outcome";

        /// <summary>The <c>SigningErrorReason</c> of a refused signature.</summary>
        public const string Reason = "simplesign.reason";

        /// <summary>The validation indication (<c>Valid</c>, <c>Invalid</c>, <c>Indeterminate</c>).</summary>
        public const string Indication = "simplesign.indication";

        /// <summary>Whether a CRL came from a cache.</summary>
        public const string CacheHit = "simplesign.cache.hit";

        /// <summary>The host name of the server called (no path, no query).</summary>
        public const string ServerAddress = "server.address";

        /// <summary>The number of trust anchors a trusted list gave.</summary>
        public const string TrustAnchors = "simplesign.trust_anchors";
    }

    /// <summary>The values of <see cref="Tags.Outcome"/>.</summary>
    public static class Outcomes
    {
        /// <summary>Done: a signature made, a token or response received, a list read.</summary>
        public const string Success = "success";

        /// <summary>Refused by a check (a signing policy constraint, a list that does not verify).</summary>
        public const string Refused = "refused";

        /// <summary>Failed: a network error, a bad response, an exception.</summary>
        public const string Error = "error";

        /// <summary>The OCSP responder or CRL says a certificate is revoked.</summary>
        public const string Revoked = "revoked";
    }
}
