# Manual de administración

Para quien instala, configura y opera una solución construida sobre `SimpleSign.Peru.Iofe.Accredited`.

## 1. Requisitos

- .NET 8 o .NET 10 en Windows, Linux o macOS.
- Para firmar: un módulo criptográfico (HSM) con controlador PKCS#11, certificado FIPS 140-2 o Common Criteria
  EAL 4+, con la clave de firma y su certificado emitido por una Entidad de Certificación acreditada ante el INDECOPI.
- Salida de red hacia: los puntos de distribución de CRL y los servicios OCSP de la cadena del certificado, la
  autoridad de sellado de tiempo (si se usa) y `https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`.

## 2. Instalación

```bash
dotnet add package SimpleSign.Peru.Iofe.Accredited
```

Para la línea de comandos, instale la herramienta y, en ella, la extensión de la IOFE:

```bash
dotnet tool install --global SimpleSign.Cli
simplesign extension install SimpleSign.Peru.Iofe.Cli
simplesign extension list
```

La extensión queda en `~/.simplesign/extensions/iofe` (o en la carpeta indicada por `SIMPLESIGN_EXTENSIONS_DIR`).
`extension install` muestra el origen del paquete y su resumen SHA-512: consérvelos como registro de instalación.
Para una instalación sin acceso a Internet, descargue el paquete y use `--source <carpeta>`.

### Verificación de la autenticidad del software (Req. 17, 27)

Antes de desplegar, verifique la firma de cada paquete descargado:

```bash
dotnet nuget verify SimpleSign.Peru.Iofe.Accredited.<versión>.nupkg --all
```

El resultado muestra la firma y el certificado utilizados; consérvelo como registro de instalación. nuget.org firma
todo paquete que distribuye (firma de repositorio).

> **Pendiente del proveedor.** La Guía pide además que la aplicación esté firmada con un certificado de firma de código
> emitido por una EC reconocida por los sistemas operativos. La firma de autor de los paquetes y la firma Authenticode
> de los ensamblados dependen de ese certificado y aún no forman parte de la publicación. Hasta entonces este
> requerimiento no está cumplido por el paquete por sí solo: quien acredita un producto debe firmar su propio
> instalador o ejecutable con su certificado de firma de código.

## 3. El módulo criptográfico (Req. 15)

La librería firma **únicamente** a través de PKCS#11. No acepta archivos de certificado con clave (PKCS#12) ni claves
en memoria, y nunca lee, exporta ni copia la clave privada.

Al abrir el módulo comprueba y, si falla, rechaza la operación y lo registra en la auditoría:

| Comprobación | Rechazo |
|---|---|
| El controlador declara la clave como sensible (`CKA_SENSITIVE`) y no extraíble (`CKA_EXTRACTABLE` falso) | `KeyNotInModule` |
| El fabricante y el modelo del token coinciden con los declarados en `ModuleDeclaration` | `ModuleMismatch` |

Para conocer el fabricante y el modelo tal como los informa el controlador:

```bash
simplesign pkcs11 list --lib /ruta/al/controlador.so
```

La certificación FIPS 140-2 o Common Criteria del módulo **no puede comprobarse por software**: es una declaración del
operador (`Certification`, `CertificateNumber`) que el auditor contrasta con el certificado del fabricante.

### Lo que corresponde al operador

Los siguientes controles de la Guía son de operación del módulo y no los puede ejercer una librería. Deben constar en
los procedimientos del operador:

- acceso a la clave privada y a sus copias bajo control de al menos dos personas, desde su generación;
- importación y exportación de claves cifradas, con una clave bajo control de dos personas;
- registros de auditoría de la generación, exportación, transporte, revocación, expiración y eliminación de la clave
  (los genera el módulo criptográfico);
- protección física del módulo bajo control de dos personas, con registro de sus movimientos y de los de los respaldos,
  y administración asignada a roles bajo responsabilidad contractual;
- solicitud del certificado conforme a PKCS#10;
- solicitud inmediata de revocación ante el compromiso de la clave.

## 4. Confianza: la lista de servicios de confianza (TSL)

Por defecto se confía en la TSL del INDECOPI. En cada carga la librería:

1. verifica la firma de la lista contra el certificado con que el INDECOPI la firma (incluido en el paquete
   `SimpleSign.Peru.Iofe`; puede indicarse otro con `TrustedListSigners` o `--tsl-signer`);
2. rechaza la lista si su fecha de próxima actualización ya pasó;
3. rechaza una lista con número de secuencia menor que la vigente;
4. la vuelve a descargar cada 6 horas y al llegar su próxima actualización, sin interrumpir las operaciones en curso.

Con `CacheFile` se conserva la última copia válida, que se usa si la descarga falla mientras la lista siga vigente.

> Confirme con el INDECOPI, por un canal independiente, la huella del certificado que firma la TSL antes de poner la
> solución en producción. La huella de la copia incluida está en `src/Extensions/Peru/Iofe/docs/iofe.md`.

Como alternativa (la "consulta manual" de la Guía), `IofeTrust.InstalledRoots` o `--trust-root` limitan la confianza a
los certificados raíz que el operador instala.

## 5. Verificaciones del certificado: siempre activas (Req. 11–14, 21–24)

Antes de cada firma, y para cada firma de un documento recibido, se verifica:

| Verificación | Motivo de rechazo |
|---|---|
| El certificado encadena a una raíz de confianza | `UntrustedRoot` |
| Ni el certificado ni ninguno de su cadena está revocado (OCSP o CRL) | `CertificateRevoked` |
| El estado de revocación se pudo obtener; la CRL está firmada por su EC, vigente y con próxima actualización | `RevocationStatusUnknown` |
| El certificado y su cadena no han expirado | `CertificateExpired`, `ChainCertificateNotValid` |
| El certificado tiene activo el bit nonRepudiation | `KeyUsageNotPermitted` |
| RSA de 2048 bits o más, o ECDSA de 256 o más; SHA-2 o SHA-3; sin SHA-1 ni MD5 en la cadena | `KeyTooWeak`, `AlgorithmNotPermitted` |

No existe parámetro, archivo ni variable de entorno que desactive estas verificaciones.

### Contingencia

La única excepción es la que la Guía prevé: un caso de contingencia operado conforme a un procedimiento aprobado por
el INDECOPI. Se declara con la referencia del procedimiento y su vigencia:

```csharp
Contingency = new IofeContingency("PROC-AAC-07", desde, hasta)
```

Mientras está vigente, se firma o se acepta un documento aunque el estado de revocación **no pueda obtenerse**. Un
certificado que se sabe revocado o expirado se sigue rechazando. Cada registro de auditoría hecho bajo contingencia
lleva la referencia del procedimiento. Vencida la vigencia, toda operación se rechaza (`ContingencyExpired`) hasta
retirar la declaración.

## 6. Tipos de transacción (Req. 14)

El agente de firma se configura con la lista cerrada de tipos de transacción para los que firma (`Transactions`).
Una firma solicitada para otro tipo se rechaza (`TransactionNotAllowed`) y queda registrada. Los derechos de
administración del sistema no dan una vía alternativa: la única forma de firmar es `Sign…Async(documento, transacción)`.

## 7. Registros de auditoría (Req. 14, 24)

| Registro | Contenido |
|---|---|
| Firmas (`JsonLinesAuditSink`) | Cada firma hecha o rechazada: fecha, formato, transacción (`tipo/id`), nivel, resultado y motivo, certificado (titular, emisor, serie, SHA-256), política y su resumen, SHA-256 de entrada y de salida |
| Verificaciones (`JsonLinesVerificationAuditSink`) | Cada documento verificado: fecha, formato, SHA-256, emisor, referencia, aceptado o rechazado, indicación de cada firma, motivos, si el comunicado se entregó, política, contingencia |

Un agente no se crea sin su registro de auditoría (`AuditMissing`), y una operación no se devuelve sin haber escrito
su registro.

Cada línea lleva el resumen de la anterior, de modo que una línea modificada, eliminada o insertada rompe la cadena:

```bash
simplesign audit verify /var/log/firma/auditoria.jsonl
simplesign audit verify /var/log/firma/verificacion.jsonl
```

La cadena evidencia la manipulación, no la impide: guarde los archivos donde la cuenta de la aplicación no pueda
reescribirlos y envíe una copia a un sistema externo.

## 8. Sellos de tiempo (sección 4.4)

Se configura la autoridad con su dirección y **su certificado**. De cada sello recibido se verifica, antes de devolver
la firma:

| Verificación | Motivo de rechazo |
|---|---|
| El sello contiene el identificador del certificado de la autoridad consultada | `TimestampUntrusted` |
| La firma del sello es válida | error de firma del sello |
| El certificado de la autoridad encadena a una raíz de confianza | `TimestampUntrusted` |
| El certificado de la autoridad no está revocado | `TimestampCertificateRevoked`, `TimestampRevocationStatusUnknown` |
| El certificado de la autoridad no ha expirado | `TimestampCertificateNotValid` |

La TSL del INDECOPI indica qué autoridades están acreditadas, no su dirección: solicítela a su prestador.

## 9. Control de acceso (Req. 14, 24)

La librería no abre puertos ni expone servicios. La protección contra acceso no autorizado corresponde al sistema que
la aloja: autenticación de quienes solicitan firmas, cuenta de servicio sin privilegios, restricción de red y de acceso
al módulo criptográfico.

## 10. Comunicado al emisor (sección 4.3)

Cuando un documento recibido se rechaza, el agente genera el comunicado y lo entrega al medio configurado
(`Notifier`). Si la entrega falla, la verificación falla (`NoticeNotDelivered`) y el registro lo indica: el documento
no queda rechazado en silencio.
