# Manual de usuario

Para quien opera la línea de comandos `simplesign iofe` y lee sus resultados. Los comandos `iofe` los aporta la
extensión `SimpleSign.Peru.Iofe.Cli` (`simplesign extension install SimpleSign.Peru.Iofe.Cli`; ver el manual de
administración).

## Firmar como agente automatizado

```bash
simplesign iofe sign factura.pdf --output factura-firmada.pdf \
  --pkcs11-lib /usr/lib/libCryptoki2_64.so --pkcs11-token firma --pkcs11-key sello-2026 --pin env:HSM_PIN \
  --module-manufacturer "Thales" --module-model "Luna K7" \
  --module-certification "FIPS 140-2 Level 3" --module-certificate 4090 \
  --transaction factura/F001-123 --allow factura --allow constancia \
  --audit-log /var/log/firma/auditoria.jsonl \
  --tsa https://tsa.ejemplo.pe/tsa --tsa-cert tsa.pem
```

Con la clave en un servicio de firma remota, en lugar de las opciones `--pkcs11-…` y `--module-…`:

```bash
simplesign iofe sign factura.pdf --output factura-firmada.pdf \
  --csc-url https://proveedor.ejemplo.pe/csc/v2/ --csc-credential sello-2026 --pin env:CSC_PIN \
  --csc-client-id agente-de-firma --csc-client-secret env:CSC_SECRETO \
  --service-provider "Proveedor S.A." --service-name "Firma Remota" \
  --service-accreditation "PSVA de firma remota acreditado ante el INDECOPI" --service-reference "Res. 000-2025/DGI-INDECOPI" \
  --transaction factura/F001-123 --allow factura --allow constancia \
  --audit-log /var/log/firma/auditoria.jsonl
```

| Opción | Significado |
|---|---|
| `--format pdf\|xml\|cms` | Formato de la firma; por defecto, según la extensión del archivo |
| `--detached` | En CMS, deja el contenido fuera de la firma |
| `--pkcs11-lib`, `--pkcs11-token`, `--pkcs11-key`, `--pin` | El módulo criptográfico, la clave y el PIN (`env:NOMBRE` lo lee de una variable de entorno) |
| `--module-…` | El módulo declarado y su certificación |
| `--csc-url`, `--csc-credential`, `--pin` | El servicio de firma remota (Cloud Signature Consortium API v2), la credencial y su PIN, en lugar del módulo |
| `--csc-token`, o `--csc-client-id` y `--csc-client-secret` | Cómo se autentica el agente ante el servicio (`env:NOMBRE` lee el secreto de una variable de entorno) |
| `--service-…` | El servicio declarado: prestador, nombre con que se identifica, acreditación y su referencia |
| `--chain archivo` | Certificado de una EC emisora (PEM o DER), si el módulo o el servicio solo guarda el de firma; repetible. Sin él, el emisor que falte se descarga de la dirección que el certificado indica (AIA) |
| `--transaction tipo/id` | La transacción para la que se firma |
| `--allow tipo` | Tipos de transacción permitidos a este agente |
| `--audit-log` | Registro de auditoría de firmas |
| `--tsa`, `--tsa-cert` | Autoridad de sellado de tiempo y su certificado |
| `--tsl`, `--tsl-signer`, `--trust-root` | Otra lista de confianza, o raíces instaladas, en lugar de la TSL del INDECOPI |
| `--contingency`, `--contingency-until` | Contingencia aprobada y su vigencia |

Resultado: `✓ Signed`, con el firmante, el nivel (B-B sin sello de tiempo, B-LT con él), la transacción, la política,
el módulo y la protección de la clave (o el servicio de firma remota y su credencial). Código de salida 0.

No hay opción para firmar con un archivo PKCS#12 (PFX): está fuera del alcance de la acreditación (manual de
administración, sección 3.3). Una opción que el comando no tiene es un error; no se ignora.

Si la operación se rechaza, el mensaje indica el motivo y el código de salida es distinto de 0:

| Mensaje | Qué hacer |
|---|---|
| `Refused (KeyNotInModule)` | La clave es extraíble o no es sensible: use una clave generada en el módulo como no extraíble |
| `Refused (ModuleMismatch)` | El token no es el declarado: revise `--module-manufacturer` y `--module-model` con `simplesign pkcs11 list` |
| `Refused (RemoteServiceMismatch)` | El servicio no es el declarado: revise `--service-name` con `simplesign csc list` |
| `Refused (RemoteAuthorizationNotUnattended)` | La credencial requiere que una persona la autorice: use una credencial de sello de la organización |
| `Refused (TransactionNotAllowed)` | El tipo de transacción no está en `--allow` |
| `Refused (ContingencyExpired)` | La vigencia de la contingencia terminó: retire `--contingency` |
| `Error (CertificateRevoked)` | El certificado o uno de su cadena está revocado: no puede firmar |
| `Error (RevocationStatusUnknown)` | No se pudo consultar OCSP ni la CRL: revise la salida de red |
| `Error (CertificateExpired)` | El certificado expiró |
| `Error (KeyUsageNotPermitted)` | El certificado no tiene el bit nonRepudiation |
| `Error (UntrustedRoot)` | La EC raíz no figura en la TSL, o falta el certificado de una EC emisora: el mensaje dice cuál. Cárguelo en el módulo o indíquelo con `--chain` |
| `Error (TimestampUntrusted)` | El sello no proviene de la autoridad configurada, o esta no es de confianza |
| `Error (TimestampInvalid)` | El sello recibido no es válido: su firma no verifica o no corresponde a lo enviado |
| `Error (TimestampCertificateRevoked)` | El certificado de la autoridad de sellado de tiempo está revocado |

## Verificar un documento recibido

```bash
simplesign iofe verify recibido.pdf --sender 20123456789 --contact mesa@entidad.pe --reference MP-2026-001 \
  --audit-log /var/log/firma/verificacion.jsonl --notice comunicado.txt \
  --html-report informe.html --etsi-report informe.xml
```

Se verifican **todas** las firmas del documento. El documento se acepta (código de salida 0) solo si tiene firmas y
todas son válidas. En caso contrario se rechaza (código 1) y el comunicado al emisor se escribe en `--notice`, con el
motivo de cada firma no válida.

Con `--detached archivo` se indica el contenido firmado de una firma CMS o XML separada.

## Visor (Req. 18, 28)

```bash
simplesign iofe view factura-firmada.pdf --output visor.html
```

La página, en español, muestra para cada firma: la integridad del documento, la fecha y hora de la firma (y la que
prueba el sello de tiempo), la clave pública y los datos del certificado (titular, emisor, serie, vigencia, uso de
clave, huella), los sellos de tiempo y los datos de revocación usados, la política aplicada, y los errores y avisos.

## Comprobar los registros de auditoría

```bash
simplesign audit verify /var/log/firma/auditoria.jsonl
```

`✓ Intact` indica que la cadena está íntegra; `✗ Broken at line N`, que la línea N fue modificada, eliminada o
insertada después de escrita.
