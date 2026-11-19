# Alcance de la acreditación

Datos que el Anexo B de la Guía pide registrar en el informe de auditoría.
(Traducción al español de [`scope.md`](../../accreditation/scope.md), que es el texto principal. Esta versión es la que se entrega al INDECOPI.)

| | Dato | Valor |
|---|---|---|
| a | Nombre de la aplicación | SimpleSign.Peru.Iofe.Accredited (paquete NuGet) y `simplesign iofe` (línea de comandos: la herramienta SimpleSign.Cli con la extensión SimpleSign.Peru.Iofe.Cli). La versión es la del paquete: `dotnet list package` o `simplesign version` |
| b | Funcionalidades PKI | Firma digital y verificación de firma digital. No realiza autenticación ni cifrado |
| c | Consulta de estado de revocación | CRL (HTTP, HTTPS y LDAP; RFC 5280) y OCSP (RFC 2560). OCSP se consulta primero y la CRL después |
| d | Tipo de operación | Librería para servidores y procesos desatendidos; línea de comandos |
| e | Sistemas operativos | Windows, Linux y macOS con .NET 8 o .NET 10 |
| f | Formato del documento firmado | PDF (PAdES, ETSI EN 319 142), CMS (CAdES, ETSI EN 319 122) y XML (XAdES, ETSI EN 319 132) |
| g | ¿Realiza funciones de módulo criptográfico? | No. La operación con la clave privada se realiza en el módulo criptográfico del operador, a través de PKCS#11, o en el de un servicio de firma remota declarado (Cloud Signature Consortium API v2). La librería calcula el resumen (SHA-256 o superior) con `System.Security.Cryptography` y es lo único que envía |
| h | ¿Genera copias de la clave privada? | No. La librería no lee, exporta ni almacena la clave, rechaza una clave que el módulo declare extraíble y no acepta archivos PKCS#12 (PFX) |
| i | Formato de documento a firmar | PDF; XML; cualquier archivo, para una firma CMS |
| j | Herramientas del entorno de pruebas | SimpleSign Sandbox (PKI de pruebas con CRL, OCSP, TSA, TSL y un servicio de firma remota); el guion `tools/auditoria/auditoria.py`, que ejecuta `simplesign iofe` en cada ítem del Anexo B y conserva las evidencias ([guion de la auditoría](../guion-de-auditoria.md)), contra el Sandbox o, con `--entorno`, en el entorno real: el HSM del operador, la TSL del INDECOPI y la EC real; SoftHSM2 como módulo PKCS#11 de pruebas. El SimpleSign TestBench (playbook `indecopi-guia-v4`) usa los firmadores generales y es material complementario |
| k | ¿Realiza consultas de sello de tiempo? | Sí, opcionalmente (RFC 3161), con las verificaciones de la sección 4.4 |

## Tipos de aplicación

- **Firma por agente automatizado (4.2).** Una persona jurídica firma de manera desatendida con una sola clave,
  custodiada en su módulo criptográfico. El módulo forma parte del alcance: el operador declara su fabricante, modelo y
  certificado FIPS 140-2 o Common Criteria EAL 4+.
  Alternativamente, la clave puede estar custodiada por un **servicio de firma remota**: el operador declara al
  prestador y su acreditación, y el módulo criptográfico —que es del prestador— no forma parte de la solución.
- **Verificación por agente automatizado (4.3).** El sistema recibe documentos firmados y verifica, sin intervención
  de operadores, el certificado de cada firma. El agente de verificación de este paquete **no firma** los documentos
  recibidos; por ello los requerimientos 25, 28 y 29, condicionados a que el sistema firme, no le son aplicables. Si
  el producto necesita firmarlos, lo hace con un `IofeSigningAgent`, que sí los cumple.
- **Sellos de tiempo (4.4).** Opcional, dentro del agente de firma.

## Requerimiento opcional: lista de servicios de confianza (TSL)

Se solicita su evaluación. Por defecto la aplicación confía en la TSL del INDECOPI
(<https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml>): verifica su firma contra el certificado con que el INDECOPI la
firma, rechaza una lista expirada, comprueba que la EC raíz del certificado figure en ella y la vuelve a descargar
cada 6 horas y al llegar su fecha de próxima actualización. La alternativa que la Guía admite —certificados raíz
instalados por el operador— está disponible con `IofeTrust.InstalledRoots`.

## Declaración de no aplicabilidad

| Ítem | Motivo |
|---|---|
| Req. 25, 28, 29 y sus ítems del Anexo B (V-17 a V-27, V-30, V-31) | El agente de verificación no firma los documentos recibidos |
| Ítems "en caso que la clave privada sea parte de la solución" (F-20 a F-27) | Corresponden a la operación del módulo criptográfico: ver el manual de administración. Con la clave en un servicio de firma remota no aplican: la clave y su módulo son del prestador |
| Firma con archivos PKCS#12 (PFX) | Fuera del alcance: contradice el Req. 15. El agente de firma no los acepta (manual de administración, sección 3.3) |
