# Integração

O agente ouve só em `http://127.0.0.1:{port}`. A página chama com `fetch`; as respostas são JSON. Os navegadores tratam `127.0.0.1` como endereço seguro, então uma página HTTPS consegue chamar.

## Endpoints

| Chamada | O que faz |
| --- | --- |
| `GET /api/health` | Diz que o agente está lá: `status`, `version`, `app`. Não pede permissão. |
| `GET /api/certificates` | Lista os certificados de assinatura. Opcionais: `source=store` ou `source=pkcs11`; `country=BR` (os que encadeiam numa estrutura de confiança desse país) ou `trust=icp-brasil` / `trust=govbr` (uma estrutura); `signingOnly=true` (válidos agora e aptos a assinar); e `filterIcpBrasil=true`, o filtro ICP-Brasil anterior. |
| `POST /api/sign` | Assina até 100 itens com um certificado, depois que o usuário confirma. |

Um certificado tem `name`, `thumbprint`, `issuerName`, `notBefore`, `expireDate`, `signatureAlgorithm` (RSA ou ECDSA), `userCertificateBase64`, `source` (store ou pkcs11) e `tokenLabel`.

## Na página

```js
const agent = "http://127.0.0.1:{port}";

// 1. O agente está lá?
await fetch(`${agent}/api/health`);

// 2. Os certificados do usuário (a primeira chamada pede para ele permitir o site).
const certificates = await (await fetch(`${agent}/api/certificates`)).json();

// 3. Assina o que o servidor preparou.
const [result] = await (await fetch(`${agent}/api/sign`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    thumbprint: certificates[0].thumbprint,
    hashAlgorithm: "SHA256",
    documentName: "contrato.pdf",
    signRequests: [{ id: "1", authenticatedAttributeBase64 }]
  })
})).json();

// result.signedHashBase64 volta para o servidor; result.error diz por que um item falhou.
```

`authenticatedAttributeBase64` são os bytes a assinar: atributos assinados CMS em DER (PAdES, CAdES) ou um `SignedInfo` XML-DSig canônico (XAdES). Qualquer outra coisa — um hash solto, um documento — é recusada com 400 antes de perguntar ao usuário, assim como atributos assinados cujo `signingCertificateV2` aponta outro certificado. A confirmação mostra o resumo que será assinado (algoritmo e os primeiros e últimos bytes). O agente calcula o hash com `hashAlgorithm` (SHA256, SHA384 ou SHA512) e assina: RSA com PKCS#1 v1.5, ECDSA no formato IEEE P1363 (r seguido de s). `documentName` aparece para o usuário na confirmação.

## No servidor: assinatura adiada

Com a biblioteca SimpleSign o servidor prepara o PDF, o agente assina e o servidor conclui:

```csharp
// Antes: o certificado vem de /api/certificates (userCertificateBase64).
var prepared = await DeferredSigner.Document(pdfBytes)
    .WithCertificate(certificate)
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithLevel(AdesBaselineProfile.Basic())
    .PrepareAsync();
// Guarde prepared.SessionData no servidor.
// Mande prepared.HashToSign para a página como authenticatedAttributeBase64.

// Depois: a página devolveu signedHashBase64.
byte[] signedPdf = await DeferredSigner.Resume(sessionData, sessionIntegrityKey)
    .CompleteAsync(signature);
```

O `PrepareAsync` confere o certificado com a política de assinatura da biblioteca e lança uma `SigningException` que
a página deve explicar ao usuário: `KeyUsageNotPermitted` (o certificado não serve para assinar), `KeyTooWeak` (RSA
abaixo de 2048 bits) ou `ChainCertificateNotValid` (um certificado da cadeia expirou); com
uma política de assinatura com `NotRevoked` em FAIL também `CertificateRevoked` e `RevocationStatusUnknown`, e então a cadeia
precisa ser passada com `.WithCertificate(certificate, chain)`. O `/api/certificates` marca esses certificados em
`policyIssue` (`keyUsage` ou `weakKey`), para a página poder deixá-los de fora.

## Respostas possíveis

| Status | Significado |
| --- | --- |
| 200 | Feito. Em `/api/sign`, confira `error` em cada item. |
| 400 | Pedido inválido: JSON inválido, sem `thumbprint`, fora de 1 a 100 itens, ou um item que não é atributos assinados nem um `SignedInfo`; `country` ou `trust` desconhecido. |
| 403 | O usuário recusou, ou o site está bloqueado. |
| 404 | Certificado ou endereço desconhecido. |
| 429 | Mais de 20 chamadas por minuto do mesmo site. |
| Sem resposta | O agente não está instalado, não está ativo, ou está em outra porta. |

> O site é identificado pela origem exata (esquema, host e porta). Páginas abertas de um arquivo, e origens que não são http ou https, são recusadas.
