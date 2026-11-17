# Manual del programador

Funcionamiento y configuración adecuada de la librería `SimpleSign.Peru.Iofe.Accredited` (Req. 20: "manual de
programador"). Espacio de nombres: `SimpleSign.Peru.Iofe.Accredited`. Marcos: .NET 8 y .NET 10; compatible con
Native AOT. Toda la criptografía usa `System.Security.Cryptography`; la operación con la clave privada ocurre en el
módulo PKCS#11 o en el servicio de firma remota.

```bash
dotnet add package SimpleSign.Peru.Iofe.Accredited
```

## Principio de diseño

Los tipos de este paquete **no reciben una política**. La política de firma (`IofePolicies.AgentSigning`) y la de
validación (`IofePolicies.AgentValidation`) son fijas, y no hay sobrecarga que acepte un certificado con clave, un
archivo PKCS#12 (PFX) o un firmador externo cualquiera: la clave está en un módulo PKCS#11 o en un servicio de firma
remota declarado, y en ningún otro lugar. Lo que la Guía exige se cumple por construcción; lo que el integrador
decide es dónde está la clave, dónde se escribe la auditoría, qué transacciones se firman y cómo se notifica al
emisor.

Para operaciones fuera del alcance de la acreditación están los firmadores generales de SimpleSign (`PadesSigner`,
`CadesSigner`, `XadesSigner`); no deben usarse para las operaciones acreditadas.

## Firma por agente automatizado (sección 4.2)

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.Peru.Iofe.Accredited;
using SimpleSign.Signers.Pkcs11;

await using var agent = await IofeSigningAgent.OpenAsync(new IofeSigningAgentOptions
{
    Module = new Pkcs11SignerOptions
    {
        LibraryPath = "/usr/lib/libCryptoki2_64.so",
        TokenLabel = "firma",
        KeyLabel = "sello-2026",
        Pin = pin,                                   // null: PIN-pad o ruta de autenticación protegida
    },
    ModuleDeclaration = new IofeModuleDeclaration("Thales", "Luna K7", "FIPS 140-2 Level 3", "4090"),
    Audit = new JsonLinesAuditSink("/var/log/firma/auditoria.jsonl"),
    Transactions = ["factura", "constancia"],
    Timestamp = new IofeTimestampAuthority(new Uri("https://tsa.ejemplo.pe/tsa"), tsaCertificate),   // opcional
});

IofeSignedDocument pdf = await agent.SignPdfAsync(pdfBytes, new IofeTransaction("factura", "F001-123"));
IofeSignedDocument cms = await agent.SignCmsAsync(data, new IofeTransaction("constancia", "C-77"), detached: false);
IofeSignedDocument xml = await agent.SignXmlAsync(xmlBytes, new IofeTransaction("factura", "F001-124"));
```

- `OpenAsync` carga la confianza, abre la sesión en el módulo y comprueba la clave y el módulo declarado. El agente
  mantiene una sesión abierta y puede compartirse entre hilos; libérelo con `await using`.
- `IofeSignedDocument` trae el documento firmado, el formato, el nivel alcanzado, si lleva sello de tiempo, el
  identificador de la operación (`tipo/id`), el titular y la huella del certificado, la política aplicada, si se
  firmó bajo contingencia y dónde está la clave que firmó (`KeySource`: módulo o servicio remoto).
- Nivel de la firma: B-B sin autoridad de sellado de tiempo (fecha y hora de la firma y cadena de certificados,
  protegidas por la firma); B-LT con ella (además, sello de tiempo y datos de revocación de toda la cadena).
- La cadena del certificado se completa hasta la raíz con los certificados del módulo y los de la confianza.

### Con la clave en un servicio de firma remota

En lugar de `Module` y `ModuleDeclaration` (una fuente de clave o la otra, nunca ambas):

```csharp
using SimpleSign.Signers.Cloud.Csc;

await using var agent = await IofeSigningAgent.OpenAsync(new IofeSigningAgentOptions
{
    RemoteService = new IofeRemoteService
    {
        Service = new CscClientOptions
        {
            BaseUri = new Uri("https://proveedor.ejemplo.pe/csc/v2/"),
            ClientId = clientId,                     // o AccessToken, un token de servicio obtenido aparte
            ClientSecret = clientSecret,
        },
        CredentialId = "sello-2026",
        Pin = pin,                                   // null si la credencial no lo pide
    },
    RemoteServiceDeclaration = new IofeRemoteServiceDeclaration(
        "Proveedor S.A.", "Firma Remota", "PSVA de firma remota acreditado ante el INDECOPI", "Res. 000-2025/DGI-INDECOPI"),
    Audit = new JsonLinesAuditSink("/var/log/firma/auditoria.jsonl"),
    Transactions = ["factura", "constancia"],
});
```

- El servicio habla *Cloud Signature Consortium API v2*. La librería le envía el resumen y recibe la firma; la clave
  no sale del servicio.
- `OpenAsync` pregunta primero al servicio quién es (`info`): si no es el declarado, lo rechaza
  (`RemoteServiceMismatch`) sin enviarle el secreto del cliente ni el PIN. Rechaza también una credencial que deba
  autorizar una persona (`RemoteAuthorizationNotUnattended`).
- Con credenciales de cliente, el agente renueva el token de servicio cuando expira.
- `agent.RemoteService` informa el servicio, la credencial, su modo de autorización y lo declarado; `agent.Module` es
  nulo. Todo lo demás —política, transacciones, auditoría, sello de tiempo, contingencia— es idéntico.
- Un archivo PKCS#12 (PFX) no es una fuente de clave de este paquete: ver el manual de administración, sección 3.3.

### Errores

| Excepción | Cuándo |
|---|---|
| `IofeAccreditationException` (`Refusal`) | Rechazo propio de la configuración acreditada: `KeyNotInModule`, `ModuleMismatch`, `RemoteServiceMismatch`, `RemoteAuthorizationNotUnattended`, `TransactionNotAllowed`, `AuditMissing`, `OptionsIncomplete`, `ContingencyExpired`, `NoticeNotDelivered` |
| `SigningException` (`Reason`) | Una verificación de la política rechazó el certificado, la clave, el algoritmo o el sello de tiempo: `CertificateRevoked`, `RevocationStatusUnknown`, `CertificateExpired`, `ChainCertificateNotValid`, `KeyUsageNotPermitted`, `KeyTooWeak`, `AlgorithmNotPermitted`, `UntrustedRoot`, `TimestampUntrusted`, `TimestampCertificateRevoked`… |
| `Pkcs11Exception` | El módulo no pudo abrirse o se negó a firmar (controlador, PIN, selección de clave) |
| `CloudSigningException` | El servicio de firma remota rechazó al agente o la credencial (token, secreto del cliente, clave deshabilitada). Un PIN rechazado al firmar llega dentro de una `SigningException` |

Todo rechazo de una firma solicitada, y de una clave, un módulo o un servicio que no son los debidos, queda en el
registro de auditoría antes de que la excepción llegue a quien llama. Lo que impide llegar a la clave —la lista de
confianza no pudo leerse, el módulo rechazó el PIN— se informa con su excepción y no deja registro: no hubo firma
solicitada con un certificado.

## Verificación por agente automatizado (sección 4.3)

```csharp
await using var verifier = await IofeVerificationAgent.CreateAsync(new IofeVerificationAgentOptions
{
    Audit = new JsonLinesVerificationAuditSink("/var/log/firma/verificacion.jsonl"),
    Notifier = new MiNotificador(),
});

IofeVerification result = await verifier.VerifyAsync(
    recibido,
    new IofeSender("20123456789", "mesa@entidad.pe"),
    new IofeVerificationRequest { Reference = "MP-2026-001" });

if (!result.Accepted)
{
    // result.Notice ya fue entregado al emisor; result.Reasons dice por qué.
}
```

- El formato (PDF, CMS, XML) se detecta. Para una firma separada, pase el contenido en
  `IofeVerificationRequest.DetachedContent`.
- Se validan **todas** las firmas. `Accepted` es verdadero solo si hay al menos una y todas resultan válidas
  (TOTAL-PASSED de ETSI EN 319 102-1). Una firma indeterminada —por ejemplo, sin estado de revocación— no se acepta.
- Un documento ilegible o sin firmas se rechaza con su comunicado; no produce una excepción.
- `IofeVerification` trae cada firma (`SignatureReportEntry`), los motivos, el comunicado, el informe en español
  (`ReportHtml`) y el informe ETSI TS 119 102-2 (`EtsiReportXml`).

### El comunicado al emisor

```csharp
sealed class MiNotificador : IIofeSenderNotifier
{
    public async ValueTask NotifyAsync(IofeRejectionNotice notice, CancellationToken cancellationToken) =>
        await correo.EnviarAsync(notice.Sender.Contact, "Documento rechazado", notice.Text, cancellationToken);
}
```

Si `NotifyAsync` lanza una excepción, `VerifyAsync` registra el comunicado como no entregado y lanza
`IofeAccreditationException` con `NoticeNotDelivered`.

Este agente no firma los documentos recibidos. Si el producto debe hacerlo, use un `IofeSigningAgent`.

## Sellos de tiempo (sección 4.4)

`IofeTimestampAuthority(Uri endpoint, X509Certificate2 certificate)`; con `Authorization` o `ClientCertificate` si la
autoridad los pide. El certificado es obligatorio: un sello firmado por cualquier otro se rechaza. Las verificaciones
están en el manual de administración, sección 8.

## Confianza

| | |
|---|---|
| `IofeTrust.IndecopiList()` (por defecto) | La TSL del INDECOPI, verificada y mantenida al día. Acepta `IofeExtensionOptions` (`CacheFile`, `TrustedListSigners`, `HttpClientProvider`) |
| `IofeTrust.List(extension)` | Una lista que la aplicación ya cargó (`IofeExtension.Load`, `LoadRefreshableAsync`) y mantiene ella misma |
| `IofeTrust.InstalledRoots(raíces)` | Certificados raíz instalados por el operador |

## Visor (Req. 18, 28)

```csharp
string pagina = await agent.Viewer.RenderAsync(firmado.Document);          // o verifier.Viewer
await using var visor = await IofeViewer.CreateAsync();                    // para un tercero que confía
```

Devuelve una página HTML autónoma, en español.

## Auditoría

`ISignatureAuditSink` (firmas) e `IVerificationAuditSink` (verificaciones) son interfaces: puede escribir en otro
almacén. Las implementaciones incluidas, `JsonLinesAuditSink` y `JsonLinesVerificationAuditSink`, escriben un objeto
JSON por línea, encadenados por resumen; `Verify(ruta)` devuelve 0 o el número de la primera línea que rompe la
cadena. Un sumidero que falla hace fallar la operación.

## Contingencia

```csharp
Contingency = new IofeContingency("PROC-AAC-07", desde, hasta)
```

Ver el manual de administración, sección 5. `TimeProvider` permite fijar el reloj en pruebas.

## Red

`HttpClientProvider` (`IHttpClientProvider`) da el cliente HTTP de las consultas de CRL, OCSP y sello de tiempo, y su
política de salida (`OutboundPolicy`): proxy, hosts permitidos y `AllowLdap = true` para CRL publicadas por LDAP.

## Pruebas

Para probar sin un HSM: SoftHSM2 como módulo PKCS#11 y el SimpleSign Sandbox como PKI de pruebas (CRL, OCSP, TSA,
TSL y un servicio de firma remota, con fallas activables). Las pruebas del paquete están en
`tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Accredited.Tests`: las de la clave en un servicio remoto se
ejecutan en cualquier máquina; las de token, con `scripts/tests/pkcs11.sh`. Cada prueba que demuestra un ítem del
Anexo B lleva el rasgo `AnnexB` (`dotnet test --filter "AnnexB=F-8"`).

El guion `src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py` ejecuta `simplesign iofe` en cada ítem del Anexo B
contra el Sandbox y conserva las evidencias: ver el [guion de la auditoría](../guion-de-auditoria.md).
