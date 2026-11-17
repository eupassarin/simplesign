# Acreditación ante el INDECOPI — SimpleSign.Peru.Iofe.Accredited

Documentación de la configuración acreditable de SimpleSign para la Infraestructura Oficial de Firma Electrónica
(IOFE) del Perú, conforme a la *Guía de Acreditación de Aplicaciones de Software*, versión 4.0 (INDECOPI, 2016), en
los tipos de aplicación:

| Sección de la Guía | Tipo | Componente |
|---|---|---|
| 4.2 (Req. 11–20) | Software de firma por parte de agentes automatizados, con la clave en un módulo criptográfico (PKCS#11) o en un servicio de firma remota | `IofeSigningAgent` · `simplesign iofe sign` |
| 4.3 (Req. 21–30) | Software de verificación por parte de agentes automatizados | `IofeVerificationAgent` · `simplesign iofe verify` |
| 4.4 | Funcionalidad de solicitud de sellos de tiempo | `IofeTimestampAuthority` |

El software de firma de usuario final (sección 4.1) no forma parte de este paquete, ni la firma con archivos PKCS#12
(PFX), que contradice el Req. 15.

| Documento | Para quién | Requerimiento |
|---|---|---|
| [Alcance](alcance.md) | El auditor: datos del alcance que pide el Anexo B | Anexo B |
| [Manual de administración](manual-de-administracion.md) | Quien instala, configura y opera la solución | Req. 20, 30 |
| [Manual de usuario](manual-de-usuario.md) | Quien opera los comandos y lee los resultados | Req. 20, 30 |
| [Manual del programador](manual-del-programador.md) | Quien integra la librería | Req. 20 ("manual de programador") |
| [Configuración de seguridad](configuracion-de-seguridad.md) | Los usuarios de la aplicación acreditada | Sección 5 |

La correspondencia de cada ítem del Anexo B con lo que lo evidencia está en
[`src/Extensions/Peru/Iofe/playbooks/indecopi-checklist.md`](../../playbooks/indecopi-checklist.md). El
[guion de la auditoría](../guion-de-auditoria.md) ([português](../roteiro-de-auditoria.md),
[English](../audit-walkthrough.md)) indica cómo producir y presentar esas evidencias con la configuración acreditada.

Estos manuales están también en inglés: [`en/`](en/README.md). El texto en español es el que se entrega al INDECOPI.

La acreditación la otorga el INDECOPI sobre un producto y su operación. Este paquete aporta la parte de software; los
manuales indican qué queda a cargo del operador (certificación del módulo criptográfico o acreditación del servicio de
firma remota, custodia de claves, control de acceso al sistema).
