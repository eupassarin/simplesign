# Integração

O agente ouve só em `http://127.0.0.1:{port}`. A página chama com `fetch`; as respostas são JSON. Os navegadores tratam `127.0.0.1` como endereço seguro, então uma página HTTPS consegue chamar.

## Endpoints

| Chamada | O que faz |
| --- | --- |
| `GET /api/health` | Diz que o agente está lá: `status`, `version`, `app`. Não pede permissão. |
| `GET /api/certificates` | Lista os certificados de assinatura. Opcionais: `source=store` ou `source=pkcs11`; `country=BR\|PE\|EU` (os que encadeiam numa estrutura de confiança desse país) ou `trust=icp-brasil` / `govbr` / `iofe` / `eidas` (uma estrutura); `signingOnly=true` (válidos agora e aptos a assinar); e `filterIcpBrasil=true`, o filtro ICP-Brasil anterior. Só as estruturas habilitadas nas Configurações respondem a isso. |
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

## Pedidos assinados pelo servidor

Um agente configurado com `signedRequestsRequired` só assina quando o corpo também traz `signedRequest`: um JWS em serialização compacta (RFC 7515) que o servidor emite com uma chave que o agente está configurado para confiar. O cabeçalho traz `alg` (ES256/384/512, RS256/384/512 ou PS256/384/512), `typ` `simplesign-sign-request+jws` e, opcionalmente, `kid`; as claims são `aud` `simplesign-agent`, `origin` (o site exato), `thumbprint` (o certificado), `items` (um `{ id, digest }` por item, sendo o digest o SHA-256 em base64url dos bytes a assinar), `iat`, `exp` (no máximo cinco minutos depois de `iat`) e `jti` (aceito uma vez). Um token ausente, expirado, repetido, assinado por outra chave ou que descreve outros bytes é recusado com 400 antes de perguntar ao usuário, e a confirmação passa a mostrar o `documentName` do token, não o do corpo. Num agente que não exige token, `signedRequest` é ignorado.

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
| 400 | Pedido inválido: JSON inválido, sem `thumbprint`, fora de 1 a 100 itens, ou um item que não é atributos assinados nem um `SignedInfo`; `country` ou `trust` desconhecido, ou não habilitado; `signedRequest` ausente ou inválido. |
| 403 | O usuário recusou, ou o site está bloqueado. |
| 404 | Certificado ou endereço desconhecido. |
| 429 | Mais de 20 chamadas por minuto do mesmo site. |
| 503 | A lista de confiança da estrutura pedida não está disponível offline; tente de novo em instantes. |
| Sem resposta | O agente não está instalado, não está ativo, ou está em outra porta. |

> O site é identificado pela origem exata (esquema, host e porta). Páginas abertas de um arquivo, e origens que não são http ou https, são recusadas.
