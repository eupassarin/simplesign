# Integración

El agente escucha solo en `http://127.0.0.1:{port}`. La página lo llama con `fetch`; las respuestas son JSON. Los navegadores tratan `127.0.0.1` como dirección segura, así que una página HTTPS puede llamarlo.

## Endpoints

| Llamada | Qué hace |
| --- | --- |
| `GET /api/health` | Dice que el agente está ahí: `status`, `version`, `app`. No pide permiso. |
| `GET /api/certificates` | Lista los certificados de firma. Opcionales: `source=store` o `source=pkcs11`; `country=BR\|PE\|EU` (los que encadenan con un marco de confianza de ese país) o `trust=icp-brasil` / `govbr` / `iofe` / `eidas` (un marco); `signingOnly=true` (válidos ahora y aptos para firmar); y `filterIcpBrasil=true`, el filtro ICP-Brasil anterior. Solo responden los marcos habilitados en Configuración. |
| `POST /api/sign` | Firma hasta 100 elementos con un certificado, después de que el usuario confirme. |

Un certificado tiene `name`, `thumbprint`, `issuerName`, `notBefore`, `expireDate`, `signatureAlgorithm` (RSA o ECDSA), `userCertificateBase64`, `source` (store o pkcs11) y `tokenLabel`.

## Desde la página

```js
const agent = "http://127.0.0.1:{port}";

// 1. ¿Está el agente ahí?
await fetch(`${agent}/api/health`);

// 2. Los certificados del usuario (la primera llamada le pide permitir el sitio).
const certificates = await (await fetch(`${agent}/api/certificates`)).json();

// 3. Firma lo que preparó el servidor.
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

// result.signedHashBase64 vuelve al servidor; result.error dice por qué falló un elemento.
```

## Solicitudes firmadas por el servidor

Un agente configurado con `signedRequestsRequired` solo firma cuando el cuerpo también lleva `signedRequest`: un JWS en serialización compacta (RFC 7515) que el servidor emite con una clave en la que el agente está configurado para confiar. Su cabecera lleva `alg` (ES256/384/512, RS256/384/512 o PS256/384/512), `typ` `simplesign-sign-request+jws` y, opcionalmente, `kid`; sus claims son `aud` `simplesign-agent`, `origin` (el sitio exacto), `thumbprint` (el certificado), `items` (un `{ id, digest }` por elemento, siendo el digest el SHA-256 en base64url de los bytes a firmar), `iat`, `exp` (como máximo cinco minutos después de `iat`) y `jti` (aceptado una vez). Un token ausente, vencido, repetido, firmado por otra clave o que describe otros bytes se rechaza con 400 antes de preguntarle al usuario, y la confirmación pasa a mostrar el `documentName` del token, no el del cuerpo. En un agente que no exige token, `signedRequest` se ignora.

`authenticatedAttributeBase64` son los bytes a firmar: atributos firmados CMS en DER (PAdES, CAdES) o un `SignedInfo` XML-DSig canónico (XAdES). Cualquier otra cosa — un resumen suelto, un documento — se rechaza con 400 antes de preguntarle al usuario, igual que los atributos firmados cuyo `signingCertificateV2` apunta a otro certificado. La confirmación muestra el resumen que se va a firmar (algoritmo y los primeros y últimos bytes). El agente calcula el hash con `hashAlgorithm` (SHA256, SHA384 o SHA512) y firma: RSA con PKCS#1 v1.5, ECDSA en el formato IEEE P1363 (r seguido de s). `documentName` se le muestra al usuario en la confirmación.

## En el servidor: firma diferida

Con la biblioteca SimpleSign el servidor prepara el PDF, el agente firma y el servidor lo termina:

```csharp
// Antes: el certificado viene de /api/certificates (userCertificateBase64).
var prepared = await DeferredSigner.Document(pdfBytes)
    .WithCertificate(certificate)
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithLevel(AdesBaselineProfile.Basic())
    .PrepareAsync();
// Guarde prepared.SessionData en el servidor.
// Envíe prepared.HashToSign a la página como authenticatedAttributeBase64.

// Después: la página devolvió signedHashBase64.
byte[] signedPdf = await DeferredSigner.Resume(sessionData, sessionIntegrityKey)
    .CompleteAsync(signature);
```

`PrepareAsync` comprueba el certificado con la política de firma de la biblioteca y lanza una `SigningException` que
la página debe explicarle al usuario: `KeyUsageNotPermitted` (el certificado no sirve para firmar), `KeyTooWeak` (RSA
de menos de 2048 bits) o `ChainCertificateNotValid` (un certificado de la cadena venció); con
una política de firma cuyo `NotRevoked` está en FAIL, también `CertificateRevoked` y `RevocationStatusUnknown`, y entonces la cadena
hay que pasarla con `.WithCertificate(certificate, chain)`. `/api/certificates` marca esos certificados en
`policyIssue` (`keyUsage` o `weakKey`), para que la página pueda dejarlos fuera.

## Respuestas posibles

| Estado | Significado |
| --- | --- |
| 200 | Hecho. En `/api/sign`, compruebe `error` en cada elemento. |
| 400 | Solicitud no válida: JSON no válido, sin `thumbprint`, fuera de 1 a 100 elementos, o un elemento que no son atributos firmados ni un `SignedInfo`; `country` o `trust` desconocido, o no habilitado; `signedRequest` ausente o no válido. |
| 403 | El usuario rechazó, o el sitio está bloqueado. |
| 404 | Certificado o dirección desconocidos. |
| 429 | Más de 20 llamadas por minuto del mismo sitio. |
| 503 | La lista de confianza del marco solicitado no está disponible sin conexión; inténtelo de nuevo en un momento. |
| Sin respuesta | El agente no está instalado, no está activo, o está en otro puerto. |

> El sitio se identifica por su origen exacto (esquema, host y puerto). Las páginas abiertas desde un archivo, y los orígenes que no son http o https, se rechazan.
