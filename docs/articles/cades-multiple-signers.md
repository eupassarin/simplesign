# CAdES: several signers, attached content and hash

## Co-signature (several signers of the same content)

```csharp
byte[] first = await CadesSigner.Document(contract).WithCertificate(alice).SignAsync();
byte[] both = await CadesSigner.CoSign(first, contract).WithCertificate(bob).SignAsync();

// Attached (.p7m): the content is inside, no need to pass it
byte[] p7m = await CadesSigner.CoSign(existingP7m).WithCertificate(bob).SignAsync();
```

`CoSign` returns the normal builder: policy, timestamp and LTV apply to the new signer. It refuses
data that the existing signature does not cover.

## Countersignature

A countersignature signs another signer's signature value (RFC 5652 §11.4, `id-countersignature`):

```csharp
byte[] countersigned = await CadesSigner.CounterSign(both, signerIndex: 1)
    .WithCertificate(notary)
    .SignAsync();
```

## Validate every signer

```csharp
var report = new CadesSignatureValidator(options).ValidateAll(cms, contract);
foreach (var signer in report.Signers)
{
    Console.WriteLine($"{signer.Index}: {signer.Result.SignerCertificate?.Subject} {signer.IsValid}");
    foreach (var counter in signer.CounterSignatures)
        Console.WriteLine($"   countersigned by {counter.Result.SignerCertificate?.Subject} {counter.IsValid}");
}
```

`Validate(cms, data)` keeps validating the first signer only.

## Attached content (.p7m)

```csharp
byte[] content = CadesSigner.ExtractContent(p7m);
var result = validator.Validate(p7m, originalData: null);   // validates the encapsulated content
```

## Validate with the hash only

When only the document's hash was kept:

```csharp
var result = validator.ValidateWithHash(p7s, SHA256.HashData(document), Oids.Sha256);
```

The hash must use the signature's digest algorithm.
