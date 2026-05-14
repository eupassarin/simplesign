using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// Verifies document integrity: ByteRange validation and document hash comparison.
/// All methods are static. Hot paths use streaming hash + Span&lt;byte&gt; to minimize allocations.
/// </summary>
internal static class IntegrityVerifier
{
    private const int StreamingBufferSize = 81_920; // 80 KB — matches FileStream default

    /// <summary>
    /// Validates ByteRange structure and verifies document hash matches the CMS messageDigest.
    /// Uses streaming incremental hash to avoid loading the full signed range into memory.
    /// </summary>
    internal static async Task<bool> ValidateByteRangeAsync(
        Stream pdfStream,
        PdfSignatureField field,
        CmsSignedData cmsData,
        List<string> errors,
        List<string> warnings,
        CancellationToken cancellationToken,
        ILogger? logger = null,
        bool isLastSignature = true)
    {
        var br = field.ByteRange;
        (logger ?? NullLogger.Instance).VerifyingByteRange(br.Offset1, br.Length1, br.Offset2, br.Length2);

        if (br.Offset1 != 0)
        {
            errors.Add($"ByteRange invalid: first offset must be 0, got {br.Offset1}.");
        }

        // Verify ByteRange covers the entire document — unsigned trailing content is a tampering vector.
        // For non-last signatures in incremental updates, the ByteRange is expected to end before EOF
        // because subsequent signatures append bytes to the file (per PAdES/ISO 32000 spec).
        long expectedEnd = br.Offset2 + br.Length2;
        if (pdfStream.CanSeek && expectedEnd != pdfStream.Length && isLastSignature)
        {
            warnings.Add($"ByteRange does not cover entire PDF. Expected {pdfStream.Length} bytes but ByteRange ends at {expectedEnd}. Unsigned content may be present after signature.");
        }

        try
        {
            bool integrityValid = await VerifyDocumentHashStreamingAsync(
                pdfStream, br, cmsData, warnings, cancellationToken, logger).ConfigureAwait(false);
            if (!integrityValid)
            {
                errors.Add("Document hash does not match the signed hash (document may have been tampered).");
            }
            else
            {
                (logger ?? NullLogger.Instance).ByteRangeVerified(br.Length1 + br.Length2);
            }
            return integrityValid;
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            errors.Add($"Integrity check failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Validates a document timestamp's integrity: computes the byte range hash using the algorithm
    /// from TSTInfo.messageImprint.hashAlgorithm and compares it with TSTInfo.messageImprint.hashedMessage.
    /// This is different from regular signature integrity, where the hash is in CMS messageDigest.
    /// </summary>
    internal static async Task<bool> ValidateTimestampByteRangeAsync(
        Stream pdfStream,
        PdfSignatureField field,
        string tstHashAlgOid,
        byte[] expectedHash,
        List<string> errors,
        List<string> warnings,
        bool isLastSignature,
        CancellationToken cancellationToken,
        ILogger? logger = null)
    {
        var br = field.ByteRange;
        (logger ?? NullLogger.Instance).VerifyingByteRange(br.Offset1, br.Length1, br.Offset2, br.Length2);

        if (br.Offset1 != 0)
        {
            errors.Add($"ByteRange invalid: first offset must be 0, got {br.Offset1}.");
        }

        long expectedEnd = br.Offset2 + br.Length2;
        if (pdfStream.CanSeek && expectedEnd != pdfStream.Length && isLastSignature)
        {
            warnings.Add($"ByteRange does not cover entire PDF. Expected {pdfStream.Length} bytes but ByteRange ends at {expectedEnd}.");
        }

#pragma warning disable CA5350
        var hashAlgName = tstHashAlgOid switch
        {
            Oids.Sha256 => HashAlgorithmName.SHA256,
            Oids.Sha384 => HashAlgorithmName.SHA384,
            Oids.Sha512 => HashAlgorithmName.SHA512,
            Oids.Sha1 => HashAlgorithmName.SHA1,
            _ => throw new NotSupportedException($"Timestamp digest OID '{tstHashAlgOid}' not supported.")
        };
#pragma warning restore CA5350

        try
        {
            using var incrementalHash = IncrementalHash.CreateHash(hashAlgName);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(StreamingBufferSize);
            try
            {
                pdfStream.Seek(br.Offset1, SeekOrigin.Begin);
                await HashStreamSegmentAsync(pdfStream, (int)br.Length1, incrementalHash, buffer, cancellationToken).ConfigureAwait(false);
                pdfStream.Seek(br.Offset2, SeekOrigin.Begin);
                await HashStreamSegmentAsync(pdfStream, (int)br.Length2, incrementalHash, buffer, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            Span<byte> actualHash = stackalloc byte[64];
            if (!incrementalHash.TryGetHashAndReset(actualHash, out int bytesWritten))
            {
                return false;
            }

            bool matches = actualHash[..bytesWritten].SequenceEqual(expectedHash);
            if (matches)
            {
                (logger ?? NullLogger.Instance).ByteRangeVerified(br.Length1 + br.Length2);
            }
            else
            {
                errors.Add("Document timestamp hash does not match the signed document content (document may have been tampered).");
            }
            return matches;
        }
        catch (Exception ex)
        {
            errors.Add($"Timestamp integrity check failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// and compares it with the messageDigest from CMS.
    /// </summary>
    internal static async Task<bool> VerifyDocumentHashStreamingAsync(
        Stream pdfStream,
        PdfByteRange byteRange,
        CmsSignedData cmsData,
        List<string> warnings,
        CancellationToken cancellationToken,
        ILogger? logger = null)
    {
        if (cmsData.MessageDigest is null or { Length: 0 })
        {
            return false;
        }

#pragma warning disable CA5350 // SHA-1 is required for validating legacy ICP-Brasil signatures (pre-2016)
        var hashAlgName = cmsData.DigestAlgorithmOid switch
        {
            Oids.Sha256 => HashAlgorithmName.SHA256,
            Oids.Sha384 => HashAlgorithmName.SHA384,
            Oids.Sha512 => HashAlgorithmName.SHA512,
            Oids.Sha1 => HashAlgorithmName.SHA1,
            _ => throw new NotSupportedException($"Digest OID '{cmsData.DigestAlgorithmOid}' not supported.")
        };
#pragma warning restore CA5350

        if (cmsData.DigestAlgorithmOid == Oids.Sha1)
        {
            warnings.Add("Document uses SHA-1 digest (deprecated since 2016). " +
                         "Integrity is verified but this signature is not PAdES compliant. " +
                         "Consider re-signing with SHA-256.");
        }

        using var incrementalHash = IncrementalHash.CreateHash(hashAlgName);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(StreamingBufferSize);
        try
        {
            // Hash first segment (before /Contents)
            pdfStream.Seek(byteRange.Offset1, SeekOrigin.Begin);
            await HashStreamSegmentAsync(pdfStream, (int)byteRange.Length1, incrementalHash, buffer, cancellationToken).ConfigureAwait(false);

            // Hash second segment (after /Contents)
            pdfStream.Seek(byteRange.Offset2, SeekOrigin.Begin);
            await HashStreamSegmentAsync(pdfStream, (int)byteRange.Length2, incrementalHash, buffer, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        // Finalize hash into stack-allocated buffer (max 64 bytes for SHA-512)
        Span<byte> actualHash = stackalloc byte[64];
        if (!incrementalHash.TryGetHashAndReset(actualHash, out int bytesWritten))
        {
            return false;
        }

        (logger ?? NullLogger.Instance).DocumentHashComputed(cmsData.DigestAlgorithmOid, bytesWritten);

        bool matches = actualHash[..bytesWritten].SequenceEqual(cmsData.MessageDigest);
        if (matches)
        {
            (logger ?? NullLogger.Instance).DocumentHashMatches();
        }
        else
        {
            (logger ?? NullLogger.Instance).DocumentHashMismatch();
        }

        return matches;
    }

    /// <summary>
    /// Computes the document hash and compares it with the messageDigest from CMS.
    /// Kept for unit tests that provide pre-read byte arrays.
    /// </summary>
    internal static bool VerifyDocumentHash(byte[] signedBytes, CmsSignedData cmsData, List<string> warnings, ILogger? logger = null)
    {
        if (cmsData.MessageDigest is null or { Length: 0 })
        {
            return false;
        }

        Span<byte> actualHash = stackalloc byte[64];
        int hashSize;

#pragma warning disable CA5350 // SHA-1 is required for validating legacy ICP-Brasil signatures (pre-2016)
        switch (cmsData.DigestAlgorithmOid)
        {
            case Oids.Sha256:
                SHA256.TryHashData(signedBytes, actualHash, out hashSize);
                break;
            case Oids.Sha384:
                SHA384.TryHashData(signedBytes, actualHash, out hashSize);
                break;
            case Oids.Sha512:
                SHA512.TryHashData(signedBytes, actualHash, out hashSize);
                break;
            case Oids.Sha1:
                warnings.Add("Document uses SHA-1 digest (deprecated since 2016). " +
                             "Integrity is verified but this signature is not PAdES compliant. " +
                             "Consider re-signing with SHA-256.");
                SHA1.TryHashData(signedBytes, actualHash, out hashSize);
                break;
            default:
                throw new NotSupportedException($"Digest OID '{cmsData.DigestAlgorithmOid}' not supported.");
        }
#pragma warning restore CA5350

        (logger ?? NullLogger.Instance).DocumentHashComputed(cmsData.DigestAlgorithmOid, hashSize);

        bool matches = actualHash[..hashSize].SequenceEqual(cmsData.MessageDigest);
        if (matches)
        {
            (logger ?? NullLogger.Instance).DocumentHashMatches();
        }
        else
        {
            (logger ?? NullLogger.Instance).DocumentHashMismatch();
        }

        return matches;
    }

#pragma warning disable CA5350 // SHA-1 is weak but required for validating legacy documents
    internal static byte[] ComputeSha1(byte[] data, List<string> warnings)
    {
        warnings.Add("Document uses SHA-1 digest (deprecated since 2016). " +
                     "Integrity is verified but this signature is not PAdES compliant. " +
                     "Consider re-signing with SHA-256.");
        return SHA1.HashData(data);
    }
#pragma warning restore CA5350

    private static async Task HashStreamSegmentAsync(
        Stream stream, int length, IncrementalHash hash, byte[] buffer, CancellationToken cancellationToken)
    {
        int remaining = length;
        while (remaining > 0)
        {
            int toRead = Math.Min(remaining, buffer.Length);
            int read = await stream.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException($"Unexpected end of stream with {remaining} bytes remaining.");
            }
            hash.AppendData(buffer, 0, read);
            remaining -= read;
        }
    }
}
