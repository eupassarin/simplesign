# Guion de la auditoría de acreditación (INDECOPI)

Paso a paso de lo que hay que preparar, ejecutar y mostrar al auditor para acreditar `SimpleSign.Peru.Iofe.Accredited`
y los comandos `simplesign iofe` conforme a la *Guía de Acreditación de Aplicaciones de Software* v4.0, secciones 4.2,
4.3 y 4.4. Todo lo que sigue fue ensayado en una máquina de desarrollo (macOS) contra el entorno de pruebas; lo que
no fue ensayado se indica.

Traducción al español de [`audit-walkthrough.md`](../audit-walkthrough.md), que es el texto principal.

Lo que se entrega al auditor son los manuales ([`acreditacion/`](acreditacion/README.md); en inglés,
[`accreditation/`](../accreditation/README.md)) y las evidencias que este guion produce. Este documento es para su
equipo.

## 1. Cómo funciona la acreditación

Del capítulo 6 de la Guía ("Procedimientos de evaluación"):

1. Seleccionado el auditor, este entrega la lista de requerimientos según el tipo de software.
2. El auditado **sustenta el alcance** de la acreditación y **justifica la no aplicabilidad** de lo que no aplica.
3. La sesión de auditoría es presencial: el auditado presenta **todas las evidencias de cada ítem**. El Anexo B pide
   una **captura de pantalla por requerimiento** y, cuando se usa un certificado en una prueba, la imagen de su perfil.
4. El auditor presenta un informe al auditado y a la comisión, con observaciones y recomendaciones.
5. El auditor expone las evidencias a la comisión.
6. De ser aprobado, el auditado **expone las funciones de la aplicación ante los comisionados** antes de la resolución.
7. La comisión emite la Resolución de Acreditación.

Después: **evaluación de seguimiento anual, en ambiente de producción real** (confianza, revocación y vigencia del
certificado antes de firmar), y evaluación de actualización cuando cambia el alcance. Las tasas, los plazos y los
formularios no están en la Guía: confírmelos con el INDECOPI.

A quién corresponde cada cosa:

| Al software (este guion lo demuestra) | Al operador (procedimientos y documentos propios) |
|---|---|
| Verificaciones del certificado, lista de confianza, auditoría, transacciones, clave solo en un módulo o en un servicio remoto, visor, sellos de tiempo, manuales | Certificación FIPS / Common Criteria del HSM o acreditación del prestador remoto, custodia de claves bajo control de dos personas, control de acceso al sistema, firma de código de su instalador |

## 2. Qué demuestra que es la librería acreditada

| Herramienta | ¿Usa `IofeSigningAgent` / `IofeVerificationAgent`? |
|---|---|
| `simplesign iofe sign \| verify \| view` | **Sí** |
| `auditoria.py` (este guion) | **Sí**: solo ejecuta los comandos anteriores |
| `SimpleSign.Peru.Iofe.Accredited.Tests` | **Sí** |
| El TestBench (playbooks) y `simplesign sign --profile iofe` | No: firmadores generales. Material complementario, nunca evidencia del paquete |

## 3. Requisitos previos

- .NET SDK 8 o 10, Python 3.9+, `curl`.
- Para la vía PKCS#11 del ensayo: SoftHSM2 y OpenSC (`brew install softhsm opensc openssl@3 jq`, o
  `apt-get install softhsm2 opensc openssl curl jq`).
- El día de la auditoría, en lugar del ensayo: el HSM real (o el servicio de firma remota real), el certificado real,
  la TSA real.

## 4. Levantar el entorno de ensayo

En la raíz del repositorio, en dos terminales:

```bash
dotnet run --project src/Apps/Development/SimpleSign.Sandbox -- --ephemeral
```

```bash
tools/stack/softhsm-provision.sh
```

```bash
export SOFTHSM2_CONF="$PWD/.softhsm/softhsm2.conf"
```

El primero es la PKI de pruebas (http://localhost:5300): certificados buenos y malos, CRL por HTTP/HTTPS/LDAP, OCSP,
TSA, una lista de confianza con el formato de la del INDECOPI y un servicio de firma remota. El segundo carga en un
token SoftHSM las claves de prueba, los certificados de las EC emisoras y una clave marcada como extraíble (la que el
agente debe rechazar).

Alternativa con Docker, no ensayada en esta ocasión: `tools/stack/up.sh --no-dss`. En Windows están los equivalentes
`tools/stack/*.ps1`, tampoco ensayados.

## 5. Instalar la línea de comandos y la extensión IOFE

En el ensayo, desde el código (el día de la auditoría, las versiones publicadas vienen de nuget.org):

```bash
dotnet pack src/Apps/SimpleSign.Cli -c Release -o ./nupkgs
```

```bash
dotnet pack src/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Cli -c Release -o ./nupkgs
```

```bash
dotnet tool install --global SimpleSign.Cli --add-source ./nupkgs --version 0.13.0
```

```bash
simplesign extension install SimpleSign.Peru.Iofe.Cli --source ./nupkgs
```

```bash
simplesign extension list
```

```bash
simplesign version
```

Muestre al auditor: `simplesign version` (dato "a" del alcance), `simplesign extension list` y
`simplesign iofe sign --help`, donde **no existe** opción de política, ni para omitir una verificación, ni de archivo
PFX.

Autenticidad del software (Req. 17, 27): `dotnet nuget verify <paquete>.nupkg` muestra la firma de repositorio de
nuget.org en los paquetes publicados. Un paquete generado localmente responde "The package is not signed". **La firma
de código del autor está pendiente** (sección 11).

## 6. Ejecutar el guion completo

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --key both --lang es --out evidencias
```

Son 70 escenarios; con las dos fuentes de clave, 110 ejecuciones (unos 5 minutos). Resultado del ensayo: **110
conformes, 0 no conformes, 0 omitidos**.

Para cada escenario el guion prepara el Sandbox (activa una falla, revoca, crea una credencial), ejecuta
`simplesign iofe …`, comprueba la firma o el rechazo **y su motivo**, y deshace la preparación. En `evidencias/`:

| Archivo | Qué es |
|---|---|
| `informe.en.html`, `informe.es.html` (y `.md`) | El informe por ítem del Anexo B: lo que pide la Guía, los escenarios, el resultado y cada comando con su salida |
| `NN-escenario-clave/comandos.txt` | Los comandos ejecutados y la salida de cada uno |
| `NN-…/auditoria.jsonl`, `verificacion.jsonl` | El registro de auditoría del escenario |
| `NN-…/firmado-*.pdf`, `comunicado.txt`, `visor.html` | El documento firmado, el comunicado al emisor, la página del visor |
| `NN-…/sandbox-log.json` | Las consultas que el agente hizo a la CRL, al OCSP, a la TSA y al servicio remoto |

Opciones útiles: `--key remote` (por defecto; no requiere token), `--key pkcs11`, `--list`, `-v` (muestra todo),
`--cli "ruta/simplesign"`, `--sandbox URL`.

## 7. Demostración en vivo, ítem por ítem

El auditor elige un ítem; ejecútelo y el guion narra cada paso:

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --item F-8 --key both --lang es
```

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --scenario contingencia --lang es
```

Secuencia sugerida (cada nombre es un `--scenario`):

| Qué mostrar | Escenarios | Ítems |
|---|---|---|
| Lista de confianza: vigente; de otro firmante; alterada; expirada; raíz no listada | `tsl-vigente`, `tsl-otro-firmante`, `tsl-alterada`, `tsl-expirada`, `raiz-no-listada` | F-1 a F-3 |
| CRL por HTTP, HTTPS y LDAP; de clave ajena; vencida; sin próxima actualización | `crl-http`, `crl-https`, `crl-ldap`, `crl-clave-ajena`, `crl-expirada`, `crl-sin-proxima-actualizacion` | F-5 a F-7 |
| Un revocado no firma; sin CRL ni OCSP no se firma; EC emisora revocada | `revocado`, `revocacion-no-disponible`, `cadena-revocada` | F-8, F-9 |
| OCSP: bueno, revocado, respuesta no autorizada | `ocsp-vigente`, `ocsp-revocado`, `ocsp-no-autorizado` | F-10 |
| Expirado, aún no válido, EC expirada | `expirado`, `aun-no-valido`, `ec-expirada` | F-11 |
| Sin nonRepudiation; sin uso de clave para firmar | `sin-no-repudio`, `sin-uso-de-firma` | F-12 |
| Nada se desactiva; contingencia declarada; revocado bajo contingencia; contingencia vencida | `sin-opcion-de-politica`, `contingencia`, `contingencia-revocado`, `contingencia-vencida` | F-14 |
| Auditoría: registros, cadena íntegra, cadena alterada; sin registro no se firma | `auditoria`, `sin-registro-de-auditoria` | F-15 |
| Transacción no definida | `transaccion-no-definida` | F-16 |
| **Vía PKCS#11**: clave en el módulo; clave extraíble; módulo no declarado | `clave-en-el-modulo`, `clave-extraible`, `modulo-no-declarado` | F-17 a F-19 |
| **Vía remota**: clave en el servicio; servicio no declarado; credencial que requiere a una persona | `clave-en-el-servicio-remoto`, `servicio-no-declarado`, `credencial-con-persona` | F-16 a F-19 |
| Un PFX no se acepta; PIN incorrecto | `pfx-no-aceptado`, `pin-incorrecto` | F-17, F-18 |
| Algoritmos: clave débil, SHA-1 en la cadena, algoritmos vigentes | `clave-debil`, `sha1-en-la-cadena`, `algoritmos-vigentes` | F-28 |
| Visor; datos de validación (B-LT); XML y CMS | `visor`, `datos-de-validacion`, `formatos` | F-30, F-31 |
| Sellos de tiempo: otra autoridad, sello alterado, TSA revocada, TSA expirada | `tsa-otra-autoridad`, `tsa-sello-alterado`, `tsa-revocada`, `tsa-expirada` | S-1 a S-4 |
| Verificación: válido; revocado, con comunicado; alterado; sin firmas; contingencia; auditoría | `v-valido`, `v-revocado`, `v-documento-alterado`, `v-sin-firmas`, `v-contingencia`, `v-auditoria` | V-1 a V-15, V-30 |

Para la captura de pantalla que pide el Anexo B, use la terminal con el escenario en vivo o la sección del escenario
en `informe.es.html`. El perfil del certificado usado se obtiene con `simplesign pkcs11 list --lib <controlador>` (vía
PKCS#11) o `simplesign csc list --csc-url … --csc-token …` (vía remota), y con `simplesign iofe view`.

## 8. Informe de las pruebas por ítem

```bash
dotnet test tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Accredited.Tests --framework net10.0 --filter "AnnexB~-" --logger "html;LogFileName=anexo-b.html" --results-directory evidencias/pruebas
```

```bash
dotnet test tests/unit/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Accredited.Tests --filter "AnnexB=F-8"
```

En el ensayo: 33 pasaron y 6 se omitieron, porque las pruebas de token requieren SoftHSM; en Docker,
`scripts/tests/pkcs11.sh` las ejecuta todas sin omitir ninguna. `AnnexBCoverageTests` falla si un ítem demostrable
queda sin prueba o sin escenario.

## 9. El día de la auditoría: qué cambia

| En el ensayo | El día de la auditoría |
|---|---|
| Sandbox (PKI de pruebas) | La PKI real: un certificado emitido por una EC acreditada |
| `--tsl http://localhost:5300/tl/tl.xml --tsl-signer …` | Nada: por defecto el agente usa la TSL del INDECOPI |
| Token SoftHSM, `--module-… "SoftHSM…"` | El HSM real: el `--pkcs11-lib` del fabricante y `--module-manufacturer/-model/-certification/-certificate` con los datos de su certificado FIPS 140-2 o Common Criteria |
| Servicio remoto del Sandbox | El servicio del prestador: `--csc-url`, credenciales de cliente y `--service-…` con su acreditación |
| TSA del Sandbox | La TSA contratada: `--tsa URL --tsa-cert archivo` |
| Paquetes locales | `dotnet tool install --global SimpleSign.Cli` y `simplesign extension install SimpleSign.Peru.Iofe.Cli` desde nuget.org |

En el HSM real, si el módulo solo guarda el certificado de firma, el agente completa la cadena con los certificados
de las EC emisoras indicados con `--chain archivo` o, a falta de ellos, descargados de la dirección que el propio
certificado indica (AIA). Si aun así falta un emisor, el rechazo es `UntrustedRoot` y el mensaje dice cuál. Ensayado
con un token sin los certificados de las EC: rechazó sin red, firmó con `--chain` y firmó mediante AIA.

### Ejecutar el guion en producción

El mismo guion se ejecuta en el servidor de producción, con el HSM, el certificado y la TSL reales; no se usa nada del
Sandbox. El entorno se describe en un archivo, hecho a partir del ejemplo y guardado fuera del repositorio:

```bash
cp src/Extensions/Peru/Iofe/tools/auditoria/entorno.ejemplo.json entorno.json
```

| Campo | Qué es |
|---|---|
| `pkcs11` | El controlador del HSM, la etiqueta del token y el **nombre** de la variable de entorno con el PIN (`env:HSM_PIN`). El PIN no se escribe en el archivo |
| `module` | La declaración del módulo: fabricante, modelo, certificación y número del certificado |
| `keys.default` | La etiqueta, en el HSM, de la clave del certificado de firma de la organización |
| `keys.<papel>` | Opcional: claves de certificados de prueba, si la EC los emite (`revoked`, `expired`, `no-nonrepudiation`…) |
| `chain` | Certificados de las EC emisoras, cuando el HSM solo guarda el de firma |
| `tsa` | Dirección y certificado de la TSA contratada |
| `otherRoot` | Un certificado raíz cualquiera que no emitió los anteriores: sirve a "raíz no listada", "TSL de otro firmante" y "sello de otra autoridad" |
| `received` | Opcional: documentos de terceros firmados con un certificado luego revocado, expirado, etc. |
| `trustedList.expired` | Opcional: una copia antigua de la TSL, ya vencida |
| `allow` | Escenarios con efecto sobre el módulo, que solo se ejecutan si se nombran: `pin-incorrecto` envía un PIN incorrecto una vez |

```bash
read -rs HSM_PIN && export HSM_PIN
```

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --entorno entorno.json --list --lang es
```

```bash
python3 src/Extensions/Peru/Iofe/tools/auditoria/auditoria.py --entorno entorno.json --ensayo evidencias --out evidencias-produccion --lang es
```

`--list` no ejecuta nada: dice, escenario por escenario, lo que este entorno puede mostrar y por qué no lo demás. La
ejecución corre solo esos. Los demás quedan en el informe como "no ejecutado en este entorno", con el motivo y, con
`--ensayo`, con el resultado que tuvieron en el ensayo del Sandbox, presentado como ensayo y no como evidencia del
entorno.

Lo que se ejecuta, medido ensayando este modo con un token SoftHSM y el Sandbox en el papel de producción:

| Entorno | Escenarios ejecutados |
|---|---|
| Solo el certificado de firma de la organización, la TSA y `otherRoot` | 24 de 70 |
| Más certificados de prueba (revocado, expirado, sin no repudio), documentos recibidos, TSL vencida y `pin-incorrecto` habilitado | 37 de 70 |

Solo con el certificado de la organización: TSL vigente, de otro firmante y alterada; raíz no listada; opción de
política inexistente; contingencia vencida; registros de auditoría; sin registro no se firma; transacción no definida;
clave en el módulo; módulo no declarado; PFX; visor; datos de validación con la TSA; XML y CMS; sello de otra
autoridad. En la verificación: documento válido, alterado y sin firmas; raíz no listada; TSL de otro firmante; opción
de política inexistente; auditoría; visor.

No se ejecutan fuera del Sandbox, porque dependen de una falla que ninguna EC o TSA produce a pedido: CRL de clave
ajena, vencida o sin próxima actualización; OCSP no autorizado; revocación no disponible y la contingencia que la
cubre; EC emisora revocada o expirada; RSA 1024; SHA-1 en la cadena; TSA revocada, expirada o con el sello alterado.
Tampoco los tres escenarios de la firma remota: este modo describe un HSM.

En `evidencias-produccion/`, además de lo que lista la sección 6: `00-entorno/`, con la versión de la herramienta, las
extensiones, el módulo y los certificados que contiene (titular, vigencia, huella) y el certificado de la primera
firma realizada, que es el perfil del certificado que el Anexo B pide adjuntar; y `MANIFIESTO.sha256`, con el resumen
de cada archivo.

Precauciones:

- **Son firmas reales**, hechas con la clave de la organización, sobre los documentos de prueba del guion ("Factura
  F001-123 - documento de prueba"). Cada una queda en el registro de auditoría de la propia ejecución, que es parte
  de la evidencia.
- **`pin-incorrecto`** cuenta para el bloqueo del token: ejecútelo una vez, a propósito, o déjelo con el ensayo.
- **Clave extraíble**: no se crea una en un HSM de producción para mostrar el rechazo. Queda con el ensayo.
- **Red**: el servidor debe alcanzar la TSL del INDECOPI, la CRL o el OCSP de la EC y la TSA. El escenario de la TSL
  alterada descarga la lista con Python; sin salida hacia ella, dé una copia en `trustedList.copy`.
- **No ensayado**: un HSM real y un servicio remoto real. Contra la TSL real del INDECOPI se ensayó lo que no depende
  de un certificado peruano: descargada, la lista se acepta; alterada o con otro firmante, se rechaza; y un
  certificado ajeno a ella no firma.

## 10. Completar el Anexo B

Use `evidencias/informe.es.html`: la tabla "Por ítem del Anexo B" da, para cada ítem, los escenarios y el resultado;
cada escenario tiene el comando y su salida. La correspondencia completa, con las pruebas, está en
[`playbooks/indecopi-checklist.md`](../../playbooks/indecopi-checklist.md) (tabla "Shown by the accredited package
itself"). Los datos del alcance (a–k) están en [`acreditacion/alcance.md`](acreditacion/alcance.md).

Ítems a declarar **no aplicables o a cargo del operador**, con su sustento:

| Ítems | Sustento |
|---|---|
| F-13, V-13 | El control de acceso corresponde al producto y al sistema que aloja la librería |
| F-20 a F-27, V-18 a V-27 | Custodia de la clave: operación del HSM. Con la clave en un servicio remoto, el módulo es del prestador |
| V-16, V-17, V-31 | El agente de verificación no firma los documentos recibidos |
| F-4, V-4 | Descarga periódica de la TSL: es de la librería (`IofeTrustedListSource`), demostrada con pruebas, no con un comando |
| F-29, V-29 | **Pendiente** (sección 11) |
| Sección 4.1 | Fuera del alcance de este paquete |

## 11. Lo que no está cubierto, y lo que mostró el ensayo

- **Firma de código (F-29 / V-29): pendiente.** Los paquetes no llevan firma de autor ni los ensamblados firma
  Authenticode. Depende del certificado de firma de código.
- **Un archivo PFX / PKCS#12 no es una fuente de clave** del paquete acreditado, porque contradice el Req. 15. No hay
  opción que lo habilite.
- **Sección 4.1** (software de usuario final): no está cubierta.
- **Vía remota**: la acreditación del prestador y que la clave no sea extraíble son una declaración del operador; el
  protocolo no las informa.
- El **agente de verificación** se crea antes de que haya documento: si no puede leer la lista de confianza, el
  comando falla con su motivo, pero no hay registro de verificación (no hay documento que registrar). El agente de
  firma que no llega a abrirse sí queda registrado (`AgentNotOpened`).
- El agente firma en B-B (sin TSA) o B-LT (con TSA); el paquete acreditado no produce B-LTA.

## 12. Problemas comunes

| Síntoma | Causa y solución |
|---|---|
| `Error (RevocationStatusUnknown)` contra el Sandbox | La línea de comandos rechaza direcciones locales: agregue `--allow-origin http://localhost:5300` (el guion ya lo hace) |
| `Error (UntrustedRoot)` en la vía PKCS#11 | Falta el certificado de una EC emisora y no se pudo descargar (el mensaje dice cuál): `--chain archivo`, o `tools/stack/softhsm-provision.sh --force` en el ensayo |
| Escenarios `(pkcs11)` omitidos | `SOFTHSM2_CONF` no está exportada o el token no fue aprovisionado |
| `Unknown option --…` en `simplesign iofe` | El comando no tiene esa opción; una opción desconocida es un error, a propósito |
| `Refused (ModuleMismatch)` en producción | El fabricante y el modelo declarados en `module` no son los que informa el token: verifique con `simplesign pkcs11 list --lib <controlador>` |
| Un escenario esperado figura como "no ejecutado en este entorno" | El motivo lo acompaña: falta la clave, el documento o la copia que pide en el archivo del entorno (`--list` los muestra todos) |
| El Sandbox se reinició y el token "no coincide" | Cada Sandbox `--ephemeral` tiene una PKI nueva: aprovisione de nuevo |

## 13. Orden sugerido de la presentación

1. Alcance y no aplicabilidad (`alcance.md`, sección 10) — 10 min.
2. Instalación y versión; `iofe sign --help` sin opciones para eludir — 5 min.
3. Informe del guion completo (`informe.es.html`) — 10 min.
4. Ítems en vivo, a elección del auditor (sección 7) — 30 a 40 min.
5. Registro de auditoría: `simplesign audit verify`, un registro alterado — 5 min.
6. Visor y comunicado al emisor — 5 min.
7. Informe de las pruebas por ítem — 5 min.
8. Manuales y configuración de seguridad; pendientes (sección 11) — 10 min.
