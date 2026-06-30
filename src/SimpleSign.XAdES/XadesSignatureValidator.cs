using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

/// <summary>
/// Validates XAdES digital signatures (ETSI EN 319 132).
/// Verifies XMLDSig integrity, certificate chain, timestamp tokens, and LTV data.
/// </summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class XadesSignatureValidator : IXadesSignatureValidator
{
    private readonly ValidationOptions _options;
    private readonly ITimestampValidator _timestampValidator;

    private sealed record XadesPropertyExtractionResult(
        bool HasSignedProperties,
        bool HasSignatureTimeStamp,
        bool HasCertificateValues,
        bool HasRevocationValues,
        bool HasArchiveTimeStamp,
        DateTimeOffset? SigningTime,
        X509Certificate2? SignerCert,
        string SignatureId);

    private static byte[] DecodeBase64(XmlNode el) =>
        Convert.FromBase64String(el.InnerText.Trim());

    /// <summary>Creates a new XAdES signature validator with optional options.</summary>
    public XadesSignatureValidator(
        ValidationOptions? options = null,
        ITimestampValidator? timestampValidator = null)
    {
        _options = options ?? new ValidationOptions();
        _timestampValidator = timestampValidator ?? new TimestampValidatorService();
    }

    /// <summary>Validates a signed XAdES XML document against optional trust anchors.</summary>
    public XadesValidationResult Validate(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors = null)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        var errors = new List<string>();
        var warnings = new List<string>();

        if (signedXml.Length == 0)
        {
            errors.Add("XML data is empty.");
            return new XadesValidationResult
            {
                Errors = errors,
                IsSignatureValid = false,
                IsIntegrityValid = false,
                IsCertificateChainValid = false,
                DetectedLevel = XadesLevel.Basic
            };
        }

        var doc = new XmlDocument { PreserveWhitespace = true };
        try
        {
            doc.Load(new MemoryStream(signedXml));
        }
        catch (XmlException ex)
        {
            errors.Add($"XML parsing failed: {ex.Message}");
            return new XadesValidationResult
            {
                Errors = errors,
                IsSignatureValid = false,
                IsIntegrityValid = false,
                IsCertificateChainValid = false,
                DetectedLevel = XadesLevel.Basic
            };
        }

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);

        if (doc.SelectSingleNode("//ds:Signature", ns) is not XmlElement sigElement)
        {
            errors.Add("No ds:Signature element found in the XML.");
            return new XadesValidationResult
            {
                Errors = errors,
                IsSignatureValid = false,
                IsIntegrityValid = false,
                IsCertificateChainValid = false,
                DetectedLevel = XadesLevel.Basic
            };
        }

        // Extract XAdES properties from the signature
        var extraction = XadesPropertyExtraction(sigElement, ns, errors, warnings);

        // Verify XMLDSig: workaround for XmlDsigEnvelopedSignatureTransform no-op in .NET 10
        // The enveloped transform should remove Signature elements from the node set
        // but doesn't in current .NET. At signing time, tempSig was in the document.
        // We rebuild the signing-time document structure for CheckSignature to work.
        bool sigValid = VerifyWithSignedXml(doc, sigElement, ns, errors);

        if (!sigValid)
        {
            errors.Add("XMLDSig signature is not cryptographically valid.");
        }

        // Validate QualifyingProperties Target matches Signature Id
        var qpTarget = sigElement.SelectSingleNode(
            "ds:Object/xades:QualifyingProperties", ns) as XmlElement;
        if (qpTarget is not null)
        {
            string target = qpTarget.GetAttribute("Target");
            string sigId = "#" + sigElement.GetAttribute("Id");
            if (target != sigId)
            {
                warnings.Add(
                    $"QualifyingProperties Target '{target}' does not match Signature Id '{sigId}'.");
            }
        }

        // Validate SignedProperties reference has correct Type attribute
        var signedInfoRefs = sigElement.SelectNodes(
            "ds:SignedInfo/ds:Reference[@Type]", ns);
        if (signedInfoRefs is not null)
        {
            bool foundSignedPropsType = false;
            foreach (XmlElement refEl in signedInfoRefs)
            {
                if (refEl.GetAttribute("Type") == XadesUris.SignedPropertiesType)
                {
                    foundSignedPropsType = true;
                    break;
                }
            }
            if (!foundSignedPropsType)
            {
                warnings.Add(
                    "No Reference with Type='http://uri.etsi.org/01903#SignedProperties' found.");
            }
        }

        // Fall back to manual cert extraction if not found via XAdES properties
        var signerCert = extraction.SignerCert ?? ExtractSignerCert(sigElement, ns, warnings);

        if (!extraction.HasSignedProperties)
        {
            warnings.Add("No XAdES SignedProperties found; signature may be plain XMLDSig.");
        }

        XadesLevel detectedLevel = XadesLevel.Basic;
        if (extraction.HasArchiveTimeStamp)
        {
            detectedLevel = XadesLevel.Archive;
        }
        else if (extraction.HasCertificateValues || extraction.HasRevocationValues)
        {
            detectedLevel = XadesLevel.LongTerm;
        }
        else if (extraction.HasSignatureTimeStamp)
        {
            detectedLevel = XadesLevel.Timestamped;
        }

        // Timestamp validation
        bool? tsValid = null;
        if (extraction.HasSignatureTimeStamp)
        {
            var sigValueEl = sigElement.SelectSingleNode("ds:SignatureValue", ns);
            byte[] sigValueBytes = sigValueEl is not null
                ? DecodeBase64(sigValueEl)
                : [];

            tsValid = ValidateSignatureTimeStamp(
                sigElement, ns, sigValueBytes, extraction.SigningTime, trustAnchors, warnings);
        }

        // LTV data validation (CertificateValues + RevocationValues)
        bool? ltvValid = null;
        if (extraction.HasCertificateValues || extraction.HasRevocationValues)
        {
            ltvValid = ValidateLtvData(sigElement, ns, signerCert, warnings);
        }

        // Archive timestamp validation
        bool? archiveTsValid = null;
        if (extraction.HasArchiveTimeStamp)
        {
            var sigValueEl = sigElement.SelectSingleNode("ds:SignatureValue", ns);
            byte[] sigValueBytes = sigValueEl is not null
                ? DecodeBase64(sigValueEl)
                : [];

            archiveTsValid = ValidateArchiveTimeStamp(
                sigElement, ns, sigValueBytes, extraction.SigningTime, trustAnchors, warnings);
        }

        // Certificate chain validation
        bool chainValid = ValidateCertificateChain(signerCert, trustAnchors, errors);

        return new XadesValidationResult
        {
            IsSignatureValid = sigValid,
            IsIntegrityValid = sigValid,
            IsCertificateChainValid = chainValid,
            HasValidSignatureTimeStamp = tsValid,
            IsLtvDataValid = ltvValid,
            HasValidArchiveTimeStamp = archiveTsValid,
            SignerCertificate = signerCert,
            SigningTime = extraction.SigningTime,
            DetectedLevel = detectedLevel,
            Errors = errors,
            Warnings = warnings
        };
    }

    private bool ValidateCertificateChain(
        X509Certificate2? signerCert,
        IEnumerable<X509Certificate2>? trustAnchors,
        List<string> errors)
    {
        if (signerCert is null)
        {
            errors.Add("No signer certificate found in the signature.");
            return false;
        }

        try
        {
            using var chain = new X509Chain { ChainPolicy = { TrustMode = X509ChainTrustMode.System } };
            CryptoUtility.ConfigureChainPolicy(chain, _options.CheckRevocation);

            if (trustAnchors is not null)
            {
                foreach (var anchor in trustAnchors)
                {
                    chain.ChainPolicy.CustomTrustStore.Add(anchor);
                }

                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            }

            bool chainValid = chain.Build(signerCert);
            if (!chainValid)
            {
                foreach (var status in chain.ChainStatus)
                {
                    errors.Add($"Certificate chain error: {status.Status} \u2014 {status.StatusInformation}");
                }
            }

            return chainValid;
        }
        catch (Exception ex)
        {
            errors.Add($"Certificate chain validation threw: {ex.Message}");
            return false;
        }
    }

    private static bool VerifyWithSignedXml(
        XmlDocument doc,
        XmlElement sigElement,
        XmlNamespaceManager ns,
        List<string> errors)
    {
        try
        {
            if (sigElement.SelectSingleNode("ds:SignedInfo", ns) is not XmlElement signedInfoEl)
            {
                errors.Add("Missing SignedInfo element.");
                return false;
            }

            if (sigElement.SelectSingleNode("ds:SignatureValue", ns) is not XmlElement signatureValueEl)
            {
                errors.Add("Missing SignatureValue element.");
                return false;
            }

            var keyInfoEl = sigElement.SelectSingleNode("ds:KeyInfo", ns) as XmlElement;

            // Step 1: Verify signature value (cryptographic integrity)
            // The XmlDsigEnvelopedSignatureTransform is a no-op in .NET 10,
            // so SignedXml.CheckSignature() would compute the document digest
            // over the full current document (including realSig).
            // At signing time, the document had tempSig (different content).
            // We verify signature value and digest values separately.

            // Determine hash algorithm from SignatureMethod
            if (signedInfoEl.SelectSingleNode("ds:SignatureMethod", ns) is not XmlElement sigMethodEl)
            {
                errors.Add("No SignatureMethod element found.");
                return false;
            }

            string sigMethodUri = sigMethodEl.GetAttribute("Algorithm");
            HashAlgorithmName sigHashAlg = GetHashAlgorithmFromSignatureMethod(sigMethodUri);
            if (sigHashAlg.Name is null)
            {
                errors.Add($"Unsupported signature method: {sigMethodUri}");
                return false;
            }

            // Canonicalize SignedInfo
            var siDoc = new XmlDocument { PreserveWhitespace = true };
            siDoc.AppendChild(siDoc.ImportNode(signedInfoEl, true));
            byte[] signedInfoBytes = CanonicalizeDocument(siDoc);
            byte[] signedInfoHash = CryptoUtility.ComputeHash(signedInfoBytes, sigHashAlg);

            // Get signature value
            byte[] signatureValue = DecodeBase64(signatureValueEl);

            // Get the signer certificate
            if (keyInfoEl?.SelectSingleNode(
                "ds:X509Data/ds:X509Certificate", ns) is not XmlElement certEl)
            {
                errors.Add("No X509Certificate found in KeyInfo.");
                return false;
            }

            byte[] rawCert;
            try
            {
                rawCert = DecodeBase64(certEl);
            }
            catch (Exception ex)
            {
                errors.Add($"Failed to parse certificate: {ex.Message}");
                return false;
            }

#pragma warning disable SYSLIB0057
            using X509Certificate2 signerCert = new(rawCert);
#pragma warning restore SYSLIB0057

            // Verify the signature value
            bool isRsaPss = sigMethodUri == XmlDSigUrls.RsaPssSha256
                || sigMethodUri == XmlDSigUrls.RsaPssSha384
                || sigMethodUri == XmlDSigUrls.RsaPssSha512;

            using RSA? rsa = signerCert.GetRSAPublicKey();
            if (rsa is not null)
            {
                var padding = isRsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                if (!rsa.VerifyHash(signedInfoHash, signatureValue, sigHashAlg, padding))
                {
                    return false;
                }
            }
            else
            {
                using ECDsa? ecdsa = signerCert.GetECDsaPublicKey();
                if (ecdsa is null || !ecdsa.VerifyHash(signedInfoHash, signatureValue))
                {
                    return false;
                }
            }

            // Step 2: Verify reference digests
            return VerifyReferenceDigests(doc, sigElement, signedInfoEl, ns, errors);
        }
        catch (Exception ex)
        {
            errors.Add($"XMLDSig verification threw: {ex.Message}");
            return false;
        }
    }

    private static bool VerifyReferenceDigests(
        XmlDocument doc,
        XmlElement sigElement,
        XmlElement signedInfoEl,
        XmlNamespaceManager ns,
        List<string> errors)
    {
        bool allValid = true;
        var refNodes = signedInfoEl.SelectNodes("ds:Reference", ns);

        if (refNodes is null || refNodes.Count == 0)
        {
            errors.Add("No ds:Reference elements found in SignedInfo.");
            return false;
        }

        foreach (XmlElement refEl in refNodes)
        {
            string uri = refEl.GetAttribute("URI") ?? string.Empty;

            var digestMethodEl = refEl.SelectSingleNode("ds:DigestMethod", ns);
            var digestValueEl = refEl.SelectSingleNode("ds:DigestValue", ns);

            if (digestMethodEl is not XmlElement dmEl || digestValueEl is not XmlElement dvEl)
            {
                errors.Add($"Reference URI='{uri}' is missing DigestMethod or DigestValue.");
                allValid = false;
                continue;
            }

            string digestMethodUri = dmEl.GetAttribute("Algorithm");
            HashAlgorithmName hashAlg;
            try
            {
                hashAlg = XmlDSigUrls.GetHashAlgorithmFromUri(digestMethodUri);
            }
            catch (Exception)
            {
                errors.Add($"Unsupported digest method '{digestMethodUri}' in reference URI='{uri}'.");
                allValid = false;
                continue;
            }

            string expectedDigestBase64 = dvEl.InnerText.Trim();
            byte[] expectedDigest;
            try
            {
                expectedDigest = Convert.FromBase64String(expectedDigestBase64);
            }
            catch (Exception)
            {
                errors.Add($"Invalid DigestValue in reference URI='{uri}'.");
                allValid = false;
                continue;
            }

            byte[] actualDigest;
            try
            {
                actualDigest = ComputeReferenceDigest(doc, sigElement, refEl, hashAlg, ns);
            }
            catch (Exception ex)
            {
                errors.Add($"Failed to compute digest for '{uri}': {ex.Message}");
                allValid = false;
                continue;
            }

            if (!expectedDigest.AsSpan().SequenceEqual(actualDigest))
            {
                errors.Add($"Digest mismatch for reference URI='{uri}'.");
                allValid = false;
            }
        }

        return allValid;
    }

    private static byte[] ComputeReferenceDigest(
        XmlDocument doc,
        XmlElement sigElement,
        XmlElement refEl,
        HashAlgorithmName hashAlg,
        XmlNamespaceManager ns)
    {
        string uri = refEl.GetAttribute("URI") ?? string.Empty;

        if (string.IsNullOrEmpty(uri))
        {
            bool hasEnvelopedTransform = HasEnvelopedTransform(refEl, ns);
            return ComputeDocumentDigestWithTempSig(doc, sigElement, ns, hashAlg, hasEnvelopedTransform);
        }

        if (uri.StartsWith('#'))
        {
            string id = uri[1..];
            return ComputeFragmentDigest(doc, id, hashAlg);
        }

        throw new NotSupportedException($"Reference URI scheme not supported: '{uri}'.");
    }

    private static bool HasEnvelopedTransform(XmlElement refEl, XmlNamespaceManager ns)
    {
        var transforms = refEl.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null)
        {
            return false;
        }

        foreach (XmlElement t in transforms)
        {
            if (t.GetAttribute("Algorithm") == XmlDSigUrls.EnvelopedSignatureTransform)
            {
                return true;
            }
        }

        return false;
    }

    private static byte[] ComputeDocumentDigestWithTempSig(
        XmlDocument doc,
        XmlElement sigElement,
        XmlNamespaceManager ns,
        HashAlgorithmName hashAlg,
        bool hasEnvelopedTransform)
    {
        // XmlDsigEnvelopedSignatureTransform is broken in .NET 10 (it does not
        // remove <Signature> elements).  The signing code now computes the
        // document digest by removing ALL <Signature> elements before
        // canonicalizing.  Match that here.
        var clone = (XmlDocument)doc.CloneNode(true);
        var cloneNs = new XmlNamespaceManager(clone.NameTable);
        cloneNs.AddNamespace("ds", XmlDSigUrls.DsNamespace);

        // Only remove Signature elements if the reference had an
        // EnvelopedSignatureTransform.
        if (hasEnvelopedTransform)
        {
            var signatures = clone.SelectNodes("//ds:Signature", cloneNs);
            if (signatures is not null)
            {
                for (int i = signatures.Count - 1; i >= 0; i--)
                {
                    var sig = signatures[i]!;
                    sig.ParentNode!.RemoveChild(sig);
                }
            }
        }

        byte[] canonicalBytes = CanonicalizeDocument(clone);
        return CryptoUtility.ComputeHash(canonicalBytes, hashAlg);
    }

    private static byte[] ComputeFragmentDigest(
        XmlDocument doc,
        string id,
        HashAlgorithmName hashAlg)
    {
        // Find element by Id — for SignedProperties, this is inside
        // ds:Object → xades:QualifyingProperties → xades:SignedProperties.
        // Use a broad XPath to find any element with the matching Id.
        if (doc.SelectSingleNode($"//*[@Id='{id}']") is not XmlElement element)
        {
            throw new InvalidOperationException($"Element with Id='{id}' not found.");
        }

        // Wrap in a temp doc for Exc C14N canonicalization
        var tempDoc = new XmlDocument { PreserveWhitespace = true };
        tempDoc.AppendChild(tempDoc.ImportNode(element, true));

        byte[] canonicalBytes = CanonicalizeDocument(tempDoc);
        return CryptoUtility.ComputeHash(canonicalBytes, hashAlg);
    }

    private static byte[] CanonicalizeDocument(XmlDocument doc)
    {
        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(doc);
        using var stream = (Stream)transform.GetOutput(typeof(Stream))!;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static XadesPropertyExtractionResult XadesPropertyExtraction(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        List<string> errors,
        List<string> warnings)
    {
        string signatureId = sigElement.GetAttribute("Id");
        bool hasSignedProperties = false;
        bool hasSignatureTimeStamp = false;
        bool hasCertificateValues = false;
        bool hasRevocationValues = false;
        bool hasArchiveTimeStamp = false;
        DateTimeOffset? signingTime = null;
        X509Certificate2? signerCert = null;

        if (sigElement.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) is XmlElement qualifyingProps)
        {
            if (qualifyingProps.SelectSingleNode(
                    "xades:SignedProperties", ns) is XmlElement signedProps)
            {
                hasSignedProperties = true;

                var st = signedProps.SelectSingleNode(
                    "xades:SignedSignatureProperties/xades:SigningTime", ns);
                if (st is not null && DateTimeOffset.TryParse(st.InnerText, out var parsedSt))
                {
                    signingTime = parsedSt;
                }

                var signingCert = signedProps.SelectSingleNode(
                    "xades:SignedSignatureProperties/xades:SigningCertificateV2", ns);

                if (signingCert is not null && signerCert is null)
                {
                    var certDigest = signingCert.SelectSingleNode(
                        "xades:Cert/xades:CertDigest/ds:DigestValue", ns);
                    if (certDigest is not null)
                    {
                        var hashAlg = DetectHashAlgorithm(
                            (XmlElement?)signingCert.SelectSingleNode(
                                "xades:Cert/xades:CertDigest/ds:DigestMethod", ns));
                        var expectedHash = DecodeBase64(certDigest);

                        var certNodes = sigElement.SelectNodes(
                            "ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns);
                        if (certNodes is not null)
                        {
                            foreach (XmlElement certEl in certNodes)
                            {
                                var rawCert = DecodeBase64(certEl);
                                var computedHash = CryptoUtility.ComputeHash(rawCert, hashAlg);
                                if (computedHash.AsSpan().SequenceEqual(expectedHash))
                                {
                                    try
                                    {
#if NET10_0_OR_GREATER
                                        signerCert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(rawCert);
#else
#pragma warning disable CA2000 // Ownership transferred to result record
                                        signerCert = new X509Certificate2(rawCert);
#pragma warning restore CA2000
#endif
                                    }
                                    catch (Exception ex)
                                    {
                                        warnings.Add($"Failed to load certificate from SigningCertificateV2: {ex.Message}");
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            var unsignedProps = qualifyingProps.SelectSingleNode(
                "xades:UnsignedProperties", ns);
            if (unsignedProps is not null)
            {
                // Check both nested (UnsignedSignatureProperties) and flat (pre-standardization) structures
                var unsignedSigProps = unsignedProps.SelectSingleNode(
                    "xades:UnsignedSignatureProperties", ns);

                hasSignatureTimeStamp =
                    unsignedSigProps?.SelectSingleNode("xades:SignatureTimeStamp", ns) is not null
                    || unsignedProps.SelectSingleNode("xades:SignatureTimeStamp", ns) is not null;

                hasCertificateValues =
                    unsignedSigProps?.SelectSingleNode("xades:CertificateValues", ns) is not null
                    || unsignedProps.SelectSingleNode("xades:CertificateValues", ns) is not null;

                hasRevocationValues =
                    unsignedSigProps?.SelectSingleNode("xades:RevocationValues", ns) is not null
                    || unsignedProps.SelectSingleNode("xades:RevocationValues", ns) is not null;

                var ats = unsignedSigProps?.SelectSingleNode(
                    "xades141:ArchiveTimeStamp", ns);
                ats ??= unsignedSigProps?.SelectSingleNode(
                        "xades:ArchiveTimeStamp", ns);
                ats ??= unsignedProps.SelectSingleNode(
                    "xades141:ArchiveTimeStamp", ns) ??
                    (XmlElement?)unsignedProps.SelectSingleNode(
                        "xades:ArchiveTimeStamp", ns);

                hasArchiveTimeStamp = ats is not null;
            }
        }

        return new XadesPropertyExtractionResult(
            hasSignedProperties, hasSignatureTimeStamp, hasCertificateValues,
            hasRevocationValues, hasArchiveTimeStamp, signingTime, signerCert, signatureId);
    }

    private static X509Certificate2? ExtractSignerCert(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        List<string> warnings)
    {
        try
        {
            if (sigElement.SelectSingleNode(
                "ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns) is not XmlElement certEl)
            {
                return null;
            }

            byte[] rawCert = DecodeBase64(certEl);
#pragma warning disable SYSLIB0057
            return new X509Certificate2(rawCert);
#pragma warning restore SYSLIB0057
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed to extract signer certificate from KeyInfo: {ex.Message}");
            return null;
        }
    }

    private static HashAlgorithmName GetHashAlgorithmFromSignatureMethod(string sigMethodUri)
    {
        return sigMethodUri switch
        {
            SignedXml.XmlDsigRSASHA1Url => HashAlgorithmName.SHA1,
            SignedXml.XmlDsigRSASHA256Url => HashAlgorithmName.SHA256,
            SignedXml.XmlDsigRSASHA384Url => HashAlgorithmName.SHA384,
            SignedXml.XmlDsigRSASHA512Url => HashAlgorithmName.SHA512,
            XmlDSigUrls.RsaPssSha256 => HashAlgorithmName.SHA256,
            XmlDSigUrls.RsaPssSha384 => HashAlgorithmName.SHA384,
            XmlDSigUrls.RsaPssSha512 => HashAlgorithmName.SHA512,
            XmlDSigUrls.EcdsaSha256 => HashAlgorithmName.SHA256,
            XmlDSigUrls.EcdsaSha384 => HashAlgorithmName.SHA384,
            XmlDSigUrls.EcdsaSha512 => HashAlgorithmName.SHA512,
            _ => default
        };
    }

    private static HashAlgorithmName DetectHashAlgorithm(XmlElement? digestMethodEl)
    {
        if (digestMethodEl is null)
        {
            return HashAlgorithmName.SHA256;
        }

        string? alg = digestMethodEl.GetAttribute("Algorithm");
        if (string.IsNullOrEmpty(alg))
        {
            return HashAlgorithmName.SHA256;
        }

        try
        {
            return XmlDSigUrls.GetHashAlgorithmFromUri(alg);
        }
        catch (Exception)
        {
            return HashAlgorithmName.SHA256;
        }
    }

    private bool? ValidateSignatureTimeStamp(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        byte[] signatureValueBytes,
        DateTimeOffset? signingTime,
        IEnumerable<X509Certificate2>? trustAnchors,
        List<string> warnings)
    {
        var tsEl = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties" +
            "/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:SignatureTimeStamp");

        if (tsEl is null)
        {
            return null;
        }

        var encTs = tsEl.SelectSingleNode("xades:EncapsulatedTimeStamp", ns);
        if (encTs is null)
        {
            warnings.Add("SignatureTimeStamp element found but no EncapsulatedTimeStamp.");
            return false;
        }

        byte[] timestampToken;
        try
        {
            timestampToken = DecodeBase64(encTs);
        }
        catch (Exception)
        {
            warnings.Add("EncapsulatedTimeStamp contains invalid base64.");
            return false;
        }

        TimestampValidator.CertificateChainValidatorDelegate? validateTsaChain = null;
        if (trustAnchors is not null)
        {
            validateTsaChain = (tsaCert, embeddedCerts, tsaErrors, tsaWarnings) =>
            {
                if (tsaCert is null)
                {
                    tsaErrors.Add("TSA certificate not found.");
                    return false;
                }

                using var chain = new X509Chain
                {
                    ChainPolicy =
                    {
                        TrustMode = X509ChainTrustMode.CustomRootTrust,
                        RevocationMode = X509RevocationMode.NoCheck
                    }
                };
                foreach (var anchor in trustAnchors)
                {
                    chain.ChainPolicy.CustomTrustStore.Add(anchor);
                }

                if (chain.Build(tsaCert))
                {
                    return true;
                }

                foreach (var status in chain.ChainStatus)
                {
                    tsaErrors.Add($"TSA chain: {status.Status} \u2014 {status.StatusInformation}");
                }
                return false;
            };
        }

        var tsResult = _timestampValidator.Validate(
            timestampToken,
            signatureValueBytes,
            signingTime,
            warnings,
            validateTsaChain,
            null);

        // If TimestampValidator returns null (e.g. parsing failure), treat as invalid
        // since the timestamp element is present but unverifiable.
        return tsResult ?? false;
    }

    private bool? ValidateArchiveTimeStamp(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        byte[] signatureValueBytes,
        DateTimeOffset? signingTime,
        IEnumerable<X509Certificate2>? trustAnchors,
        List<string> warnings)
    {
        // Try xades141 namespace first, fall back to xades; try nested then flat
        var atsEl = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties" +
            "/xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades141:ArchiveTimeStamp");

        atsEl ??= SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties" +
            "/xades:UnsignedSignatureProperties/xades:ArchiveTimeStamp",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:ArchiveTimeStamp");

        if (atsEl is null)
        {
            return null;
        }

        var encTs = atsEl.SelectSingleNode("xades141:EncapsulatedTimeStamp", ns);
        encTs ??= atsEl.SelectSingleNode("xades:EncapsulatedTimeStamp", ns);

        if (encTs is null)
        {
            warnings.Add("ArchiveTimeStamp element found but no EncapsulatedTimeStamp.");
            return false;
        }

        byte[] timestampToken;
        try
        {
            timestampToken = DecodeBase64(encTs);
        }
        catch (Exception)
        {
            warnings.Add("ArchiveTimeStamp EncapsulatedTimeStamp contains invalid base64.");
            return false;
        }

        // Validate TSA signature on the archive timestamp token
        TimestampValidator.CertificateChainValidatorDelegate? validateTsaChain = null;
        if (trustAnchors is not null)
        {
            validateTsaChain = (tsaCert, embeddedCerts, tsaErrors, tsaWarnings) =>
            {
                if (tsaCert is null)
                {
                    tsaErrors.Add("TSA certificate not found.");
                    return false;
                }
                using var chain = new X509Chain
                {
                    ChainPolicy =
                    {
                        TrustMode = X509ChainTrustMode.CustomRootTrust,
                        RevocationMode = X509RevocationMode.NoCheck
                    }
                };
                foreach (var anchor in trustAnchors)
                {
                    chain.ChainPolicy.CustomTrustStore.Add(anchor);
                }
                if (chain.Build(tsaCert))
                {
                    return true;
                }
                foreach (var status in chain.ChainStatus)
                {
                    tsaErrors.Add($"TSA chain: {status.Status} \u2014 {status.StatusInformation}");
                }
                return false;
            };
        }

        // Hash match is best-effort: archive timestamp covers the full signature element
        // before the archive timestamp was applied. Full verification requires
        // reconstructing the pre-archive document state.
        warnings.Add("ArchiveTimestamp hash verification is best-effort; TSA signature " +
                     "is verified but full messageImprint check requires pre-archive document state.");

        // Hash match is best-effort: archive timestamp covers the full signature element
        // before the archive timestamp was applied. Full verification requires
        // reconstructing the pre-archive document state.
        var tsResult = _timestampValidator.Validate(
            timestampToken,
            signatureValueBytes,
            signingTime,
            warnings,
            validateTsaChain,
            null);

        return tsResult ?? false;
    }

    private static bool? ValidateLtvData(
        XmlElement sigElement,
        XmlNamespaceManager ns,
        X509Certificate2? signerCert,
        List<string> warnings)
    {
        var certValues = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CertificateValues",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:CertificateValues");

        var revValues = SelectByNestedPath(sigElement, ns,
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:RevocationValues",
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:RevocationValues");

        if (certValues is null && revValues is null)
        {
            return null;
        }

        bool revValuesValid = true;

        // Validate CertificateValues
        if (certValues is not null)
        {
            try
            {
                var certNodes = certValues.SelectNodes("xades:EncapsulatedX509Certificate", ns);
                if (certNodes is null || certNodes.Count == 0)
                {
                    warnings.Add("CertificateValues element is empty.");
                    return false;
                }

                bool hasSigner = false;
                foreach (XmlElement certEl in certNodes)
                {
                    try
                    {
                        byte[] rawData = DecodeBase64(certEl);
                        if (signerCert is not null && rawData.AsSpan().SequenceEqual(signerCert.RawData))
                        {
                            hasSigner = true;
                        }
                        // Validate that the DER blob is parseable
#if NET10_0_OR_GREATER
                        using var _ = X509CertificateLoader.LoadCertificate(rawData);
#else
                        using var _ = new X509Certificate2(rawData);
#endif
                    }
                    catch (Exception)
                    {
                        warnings.Add("CertificateValues contains invalid X.509 certificate data.");
                        return false;
                    }
                }

                if (!hasSigner && signerCert is not null)
                {
                    warnings.Add("CertificateValues does not include the signer certificate.");
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Failed to validate CertificateValues: {ex.Message}");
                return false;
            }
        }

        // Validate RevocationValues
        if (revValues is not null)
        {
            try
            {
                // Check OCSP responses
                var ocspNodes = revValues.SelectNodes(
                    "xades:OCSPValues/xades:EncapsulatedOCSPValue", ns);
                if (ocspNodes is not null)
                {
                    foreach (XmlElement ocspEl in ocspNodes)
                    {
                        try
                        {
                            byte[] ocspData = DecodeBase64(ocspEl);
                            // Validate that the OCSP response is parseable DER
                            var reader = new System.Formats.Asn1.AsnReader(
                                ocspData, System.Formats.Asn1.AsnEncodingRules.DER);
                            reader.ReadSequence(); // OCSP response is a SEQUENCE
                        }
                        catch (Exception)
                        {
                            warnings.Add("EncapsulatedOCSPValue contains invalid data.");
                            revValuesValid = false;
                        }
                    }
                }

                // Check CRLs
                var crlNodes = revValues.SelectNodes(
                    "xades:CRLValues/xades:EncapsulatedCRLValue", ns);
                if (crlNodes is not null)
                {
                    foreach (XmlElement crlEl in crlNodes)
                    {
                        try
                        {
                            byte[] crlData = DecodeBase64(crlEl);
                            // Validate that the CRL data is parseable as DER
                            var reader = new System.Formats.Asn1.AsnReader(crlData, System.Formats.Asn1.AsnEncodingRules.DER);
                            reader.ReadSequence();
                        }
                        catch (Exception)
                        {
                            warnings.Add("EncapsulatedCRLValue contains invalid data.");
                            revValuesValid = false;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Failed to validate RevocationValues: {ex.Message}");
                revValuesValid = false;
            }
        }

        if (!revValuesValid)
        {
            warnings.Add("RevocationValues validation failed.");
            return false;
        }

        return true;
    }

    private static XmlElement? SelectByNestedPath(
        XmlElement root,
        XmlNamespaceManager ns,
        string nestedPath,
        string flatPath)
    {
        return root.SelectSingleNode(nestedPath, ns) as XmlElement
            ?? root.SelectSingleNode(flatPath, ns) as XmlElement;
    }
}
