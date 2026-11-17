# SimpleSign.Brazil

Shared building blocks of the SimpleSign Brazilian trust frameworks, pulled in by
`SimpleSign.Brazil.IcpBrasil` and `SimpleSign.Brazil.GovBr`: CPF and CNPJ validation and
formatting, the Lei 14.063/2020 signature levels, the advanced-signature (AEA) manifest and the
ITI VALIDAR helpers.

## Quickstart

```csharp
using SimpleSign.Brazil;

bool ok = Cpf.IsValid("123.456.789-09");
string? level = Lei14063.Classify(validationResult)?.ToString();   // Simples, Avancada, Qualificada
```

Install `SimpleSign.Brazil.IcpBrasil` and/or `SimpleSign.Brazil.GovBr` to validate signatures.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
