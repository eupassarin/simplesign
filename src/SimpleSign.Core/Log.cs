using Microsoft.Extensions.Logging;

namespace SimpleSign.Core;

/// <summary>
/// High-performance source-generated log messages for core infrastructure.
/// </summary>
internal static partial class Log
{
    // ── Revocation (24xx) ────────────────────────────────────────────

    [LoggerMessage(EventId = 2410, Level = LogLevel.Debug,
        Message = "Checking {Count} embedded CRL(s) for {Subject}")]
    internal static partial void CheckingEmbeddedCrls(this ILogger logger, int count, string subject);

    [LoggerMessage(EventId = 2401, Level = LogLevel.Warning,
        Message = "Certificate revoked (found in embedded CRL): {Subject}")]
    internal static partial void CertificateRevokedInCrl(this ILogger logger, string subject);

    [LoggerMessage(EventId = 2400, Level = LogLevel.Debug,
        Message = "Certificate not revoked (verified via embedded CRL): {Subject}")]
    internal static partial void CertificateNotRevokedInCrl(this ILogger logger, string subject);

    [LoggerMessage(EventId = 2411, Level = LogLevel.Warning,
        Message = "Embedded CRL validation failed: {Message}")]
    internal static partial void EmbeddedCrlValidationFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2412, Level = LogLevel.Debug,
        Message = "Trying OCSP for {Subject} at {OcspUrl}")]
    internal static partial void TryingOcsp(this ILogger logger, string subject, string ocspUrl);

    [LoggerMessage(EventId = 2413, Level = LogLevel.Warning,
        Message = "OCSP check failed: {Message}")]
    internal static partial void OcspCheckFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2414, Level = LogLevel.Debug,
        Message = "Trying CRL download for {Subject} from {CrlUrl}")]
    internal static partial void TryingCrlDownload(this ILogger logger, string subject, string crlUrl);

    // ── CRL Client (25xx) ────────────────────────────────────────────

    [LoggerMessage(EventId = 2510, Level = LogLevel.Debug,
        Message = "Downloading CRL from {CrlUrl}")]
    internal static partial void CrlDownloading(this ILogger logger, string crlUrl);

    [LoggerMessage(EventId = 2511, Level = LogLevel.Debug,
        Message = "CRL downloaded ({Size} bytes)")]
    internal static partial void CrlDownloaded(this ILogger logger, int size);

    [LoggerMessage(EventId = 2512, Level = LogLevel.Warning,
        Message = "CRL nextUpdate parsing failed: {Message}")]
    internal static partial void CrlNextUpdateParsingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2513, Level = LogLevel.Warning,
        Message = "CRL serial check parsing failed: {Message}")]
    internal static partial void CrlSerialCheckParsingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2514, Level = LogLevel.Warning,
        Message = "CRL signature verification failed: {Message}")]
    internal static partial void CrlSignatureVerificationFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2515, Level = LogLevel.Warning,
        Message = "CRL URL extension parsing failed: {Message}")]
    internal static partial void CrlUrlExtensionParsingFailed(this ILogger logger, string message);

    // ── OCSP Client (26xx) ───────────────────────────────────────────

    [LoggerMessage(EventId = 2610, Level = LogLevel.Debug,
        Message = "Sending OCSP request to {OcspUrl}")]
    internal static partial void OcspRequestSending(this ILogger logger, string ocspUrl);

    [LoggerMessage(EventId = 2611, Level = LogLevel.Debug,
        Message = "OCSP response received ({Size} bytes)")]
    internal static partial void OcspResponseReceived(this ILogger logger, int size);

    [LoggerMessage(EventId = 2612, Level = LogLevel.Warning,
        Message = "OCSP responder cert loading failed: {Message}")]
    internal static partial void OcspResponderCertLoadingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2613, Level = LogLevel.Warning,
        Message = "OCSP signature verification failed: {Message}")]
    internal static partial void OcspSignatureVerificationFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2614, Level = LogLevel.Warning,
        Message = "OCSP URL extension parsing failed: {Message}")]
    internal static partial void OcspUrlExtensionParsingFailed(this ILogger logger, string message);

    // ── Timestamp Client (27xx) ──────────────────────────────────────

    [LoggerMessage(EventId = 2710, Level = LogLevel.Debug,
        Message = "Timestamp nonce generated, sending request to {TsaUrl}")]
    internal static partial void TimestampNonceSending(this ILogger logger, string tsaUrl);

    [LoggerMessage(EventId = 2711, Level = LogLevel.Debug,
        Message = "Timestamp response received ({Size} bytes)")]
    internal static partial void TimestampResponseReceived(this ILogger logger, int size);

    [LoggerMessage(EventId = 2712, Level = LogLevel.Warning,
        Message = "Nonce verification skipped: {Message}")]
    internal static partial void NonceVerificationSkipped(this ILogger logger, string message);

    [LoggerMessage(EventId = 2713, Level = LogLevel.Debug,
        Message = "Skipping unhealthy TSA {TsaUrl} (failures: {Failures})")]
    internal static partial void TsaSkippingUnhealthy(this ILogger logger, string tsaUrl, int failures);

    [LoggerMessage(EventId = 2714, Level = LogLevel.Information,
        Message = "TSA failover: switched primary from {Old} to {New}")]
    internal static partial void TsaFailover(this ILogger logger, string old, string @new);

    // ── Integrity & Crypto Verification (21xx) ───────────────────

    [LoggerMessage(EventId = 2110, Level = LogLevel.Debug,
        Message = "Verifying cryptographic signature: algorithm={Algorithm}, cert={Subject}")]
    internal static partial void VerifyingCryptoSignature(this ILogger logger, string algorithm, string subject);

    [LoggerMessage(EventId = 2111, Level = LogLevel.Debug,
        Message = "Cryptographic signature verified successfully")]
    internal static partial void CryptoSignatureVerified(this ILogger logger);

    [LoggerMessage(EventId = 2112, Level = LogLevel.Debug,
        Message = "Validating SigningCertificateV2: issuer={Issuer}, serial={Serial}")]
    internal static partial void ValidatingSigningCertV2(this ILogger logger, string issuer, string serial);

    [LoggerMessage(EventId = 2201, Level = LogLevel.Warning,
        Message = "Cryptographic signature verification failed")]
    internal static partial void SignatureInvalid(this ILogger logger);

    [LoggerMessage(EventId = 2202, Level = LogLevel.Error,
        Message = "Signature verification error")]
    internal static partial void SignatureError(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 2302, Level = LogLevel.Error,
        Message = "Certificate chain validation error")]
    internal static partial void ChainError(this ILogger logger, Exception ex);

    // ── CMS Parser (28xx) ────────────────────────────────────────────

    [LoggerMessage(EventId = 2810, Level = LogLevel.Warning,
        Message = "Embedded cert loading failed: {Message}")]
    internal static partial void EmbeddedCertLoadingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2811, Level = LogLevel.Warning,
        Message = "Unsigned attribute parsing failed: {Message}")]
    internal static partial void UnsignedAttributeParsingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2812, Level = LogLevel.Warning,
        Message = "GeneralizedTime parsing failed: {Message}")]
    internal static partial void GeneralizedTimeParsingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2813, Level = LogLevel.Warning,
        Message = "SigningCertificateV2 parsing failed: {Message}")]
    internal static partial void SigningCertificateV2ParsingFailed(this ILogger logger, string message);

    // ── Timestamp Validator (36xx) ───────────────────────────────────

    [LoggerMessage(EventId = 3610, Level = LogLevel.Warning,
        Message = "Timestamp genTime extraction failed: {Message}")]
    internal static partial void TimestampGenTimeExtractionFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3611, Level = LogLevel.Warning,
        Message = "TSA cert loading failed: {Message}")]
    internal static partial void TsaCertLoadingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3612, Level = LogLevel.Warning,
        Message = "TSA data extraction failed: {Message}")]
    internal static partial void TsaDataExtractionFailed(this ILogger logger, string message);

    // ── HTTP Resilience (35xx) ───────────────────────────────────────

    [LoggerMessage(EventId = 3510, Level = LogLevel.Warning,
        Message = "GET {Url} failed after {MaxRetries} retries: {Error}")]
    internal static partial void HttpGetFailed(this ILogger logger, string url, int maxRetries, string error);

    // ── Certificate Chain Utility (33xx) ─────────────────────────────

    [LoggerMessage(EventId = 3310, Level = LogLevel.Warning,
        Message = "Certificate loading failed: {Message}")]
    internal static partial void CertificateLoadingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3311, Level = LogLevel.Warning,
        Message = "PKCS12 collection loading failed: {Message}")]
    internal static partial void Pkcs12CollectionLoadingFailed(this ILogger logger, string message);

    // ── ICP-Brasil Chain Validator (31xx) ─────────────────────────────

    [LoggerMessage(EventId = 3110, Level = LogLevel.Warning,
        Message = "SAN parsing failed: {Message}")]
    internal static partial void SanParsingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3111, Level = LogLevel.Warning,
        Message = "Root cert download failed: {Message}")]
    internal static partial void RootCertDownloadFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3112, Level = LogLevel.Warning,
        Message = "Root cert loading failed: {Message}")]
    internal static partial void RootCertLoadingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3113, Level = LogLevel.Warning,
        Message = "OID encoding failed: {Message}")]
    internal static partial void OidEncodingFailed(this ILogger logger, string message);

    // ── Gov.br Chain Validator (32xx) ────────────────────────────────

    [LoggerMessage(EventId = 3210, Level = LogLevel.Debug,
        Message = "Validating Gov.br certificate: {Subject}")]
    internal static partial void GovBrValidating(this ILogger logger, string subject);

    // ── CMS Builder (4xxx) ─────────────────────────────────────────

    [LoggerMessage(EventId = 4000, Level = LogLevel.Debug,
        Message = "Building CMS/PKCS#7: digest={DigestAlgorithm}, sigAlg={SignatureAlgorithm}, cert={Subject}")]
    internal static partial void CmsBuildStarted(this ILogger logger, string digestAlgorithm, string signatureAlgorithm, string subject);

    [LoggerMessage(EventId = 4001, Level = LogLevel.Debug,
        Message = "Content hash computed ({HashSize} bytes) using {Algorithm}")]
    internal static partial void CmsContentHashComputed(this ILogger logger, int hashSize, string algorithm);

    [LoggerMessage(EventId = 4002, Level = LogLevel.Debug,
        Message = "Signed attributes built ({Size} bytes), {ExtraCount} extra attribute(s)")]
    internal static partial void CmsSignedAttributesBuilt(this ILogger logger, int size, int extraCount);

    [LoggerMessage(EventId = 4003, Level = LogLevel.Debug,
        Message = "Signature generated ({Size} bytes), padding={Padding}")]
    internal static partial void CmsSignatureGenerated(this ILogger logger, int size, string padding);

    [LoggerMessage(EventId = 4004, Level = LogLevel.Debug,
        Message = "CMS SignedData assembled ({Size} bytes), {CertCount} certificate(s) embedded")]
    internal static partial void CmsSignedDataAssembled(this ILogger logger, int size, int certCount);

    [LoggerMessage(EventId = 4005, Level = LogLevel.Debug,
        Message = "External signer invoked, awaiting signature for {Size} bytes of signed attributes")]
    internal static partial void CmsExternalSignerInvoked(this ILogger logger, int size);

    [LoggerMessage(EventId = 4006, Level = LogLevel.Debug,
        Message = "External signature received ({Size} bytes)")]
    internal static partial void CmsExternalSignatureReceived(this ILogger logger, int size);
}
