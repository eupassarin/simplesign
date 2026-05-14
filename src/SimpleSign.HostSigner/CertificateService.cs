using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.HostSigner;

internal static class CertificateService
{
    public static List<CertificateInfo> ListSigningCertificates(bool filterIcpBrasil)
    {
        var result = new List<CertificateInfo>();
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        foreach (var cert in store.Certificates)
        {
            if (!cert.HasPrivateKey) continue;

            // Only signing certs (digitalSignature or nonRepudiation)
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509KeyUsageExtension ku &&
                    (ku.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) == 0)
                {
                    goto next;
                }
            }

            if (filterIcpBrasil)
            {
                var issuer = cert.Issuer;
                if (!issuer.Contains("ICP-Brasil", StringComparison.OrdinalIgnoreCase) &&
                    !issuer.Contains("AC ", StringComparison.OrdinalIgnoreCase))
                {
                    goto next;
                }
            }

            var (algoName, hashName) = DetectAlgorithms(cert);

            result.Add(new CertificateInfo
            {
                Name = cert.Subject,
                Thumbprint = cert.Thumbprint,
                IssuerName = cert.Issuer,
                NotBefore = cert.NotBefore.ToString("o"),
                ExpireDate = cert.NotAfter.ToString("o"),
                SignatureAlgorithm = algoName,
                HashAlgorithm = hashName,
                UserCertificateBase64 = Convert.ToBase64String(cert.RawData),
            });

            next:;
        }

        return result;
    }

    public static List<SignResult> SignHashes(SignRequest request)
    {
        var results = new List<SignResult>();

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, request.Thumbprint!, false);
        if (matches.Count == 0)
        {
            return [new SignResult { Id = "0", Error = $"Certificate not found: {request.Thumbprint}" }];
        }

        var cert = matches[0];
        using var key = cert.GetRSAPrivateKey() ?? (AsymmetricAlgorithm?)cert.GetECDsaPrivateKey();

        if (key is null)
        {
            return [new SignResult { Id = "0", Error = "No RSA or ECDSA private key available" }];
        }

        var hashAlgName = ParseHashAlgorithm(request.HashAlgorithm);

        for (int i = 0; i < (request.SignRequests?.Count ?? 0); i++)
        {
            var sr = request.SignRequests![i];
            var id = sr.Id ?? i.ToString();

            try
            {
                var dataToSign = Convert.FromBase64String(sr.AuthenticatedAttributeBase64 ?? "");
                byte[] signature;

                if (key is RSA rsa)
                {
                    signature = rsa.SignData(dataToSign, hashAlgName, RSASignaturePadding.Pkcs1);
                }
                else if (key is ECDsa ecdsa)
                {
                    signature = ecdsa.SignData(dataToSign, hashAlgName);
                }
                else
                {
                    results.Add(new SignResult { Id = id, Error = "Unsupported key type" });
                    continue;
                }

                results.Add(new SignResult
                {
                    Id = id,
                    SignedHashBase64 = Convert.ToBase64String(signature),
                });
            }
            catch (Exception ex)
            {
                results.Add(new SignResult { Id = id, Error = ex.Message });
            }
        }

        return results;
    }

    private static (string algo, string hash) DetectAlgorithms(X509Certificate2 cert)
    {
        try
        {
            if (cert.GetRSAPrivateKey() is not null) return ("RSA", "SHA256");
        }
        catch { /* key not accessible */ }

        try
        {
            if (cert.GetECDsaPrivateKey() is not null) return ("ECDSA", "SHA256");
        }
        catch { /* key not accessible */ }

        return ("RSA", "SHA256");
    }

    private static HashAlgorithmName ParseHashAlgorithm(string? name) => name?.ToUpperInvariant() switch
    {
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
        "SHA1" => HashAlgorithmName.SHA1,
        _ => HashAlgorithmName.SHA256,
    };
}
