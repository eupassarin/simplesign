# Configuración de seguridad (sección 5 de la Guía)

Configuración que debe implementarse para que la aplicación cumpla todos los requerimientos. Los usuarios de la
aplicación son responsables de aplicarla y mantenerla actualizada.
(Traducción al español de [`security-configuration.md`](../../accreditation/security-configuration.md), que es el texto principal. Esta versión es la que se entrega al INDECOPI.)

La mayor parte de los requerimientos **no depende de configuración**: la política de verificación del certificado es
fija y la librería no ofrece ningún parámetro para desactivarla. Lo que sigue es lo que sí depende de quien la instala.

| # | Configuración | Por qué |
|---|---|---|
| 1 | Usar únicamente `IofeSigningAgent` e `IofeVerificationAgent` (o `simplesign iofe`) para las operaciones acreditadas. Los firmadores generales de SimpleSign (`PadesSigner`, `CadesSigner`, `XadesSigner`) aceptan políticas y claves que la acreditación no cubre | Req. 14, 15, 24 |
| 2 | Custodiar la clave privada en un módulo criptográfico con certificación FIPS 140-2 o Common Criteria EAL 4+, generada en el módulo y no extraíble (`CKA_SENSITIVE` verdadero, `CKA_EXTRACTABLE` falso); o en un servicio de firma remota acreditado ante el INDECOPI o con dispositivo de firma certificado. No usar archivos PKCS#12 (PFX) para las operaciones acreditadas | Req. 15 |
| 3 | Declarar en `ModuleDeclaration` el fabricante y el modelo tal como los informa el controlador (`simplesign pkcs11 list`), la certificación y el número de su certificado; o en `RemoteServiceDeclaration` el prestador, el nombre con que el servicio se identifica (`simplesign csc list`), su acreditación y la referencia de esta | Req. 15 |
| 4 | No escribir el PIN, el token de servicio ni el secreto del cliente en archivos ni en la línea de comandos: usar una variable de entorno (`--pin env:NOMBRE`, `--csc-client-secret env:NOMBRE`) o el almacén de secretos de la plataforma | Req. 14 |
| 5 | Escribir los registros de auditoría en un volumen que la cuenta de la aplicación solo pueda ampliar, y copiarlos a un sistema externo. Verificar la cadena periódicamente: `simplesign audit verify <archivo>` | Req. 14, 24 |
| 6 | Definir en `Transactions` solo los tipos de transacción que el agente debe firmar | Req. 14 |
| 7 | Permitir la salida de red hacia los puntos de distribución de CRL, los servicios OCSP, la autoridad de sellado de tiempo, la TSL del INDECOPI y, si la clave está en un servicio de firma remota, la dirección `https` de ese servicio. Para CRL publicadas por LDAP, habilitar `AllowLdap` en la política de salida (`--allow-ldap`) | Req. 11, 21 |
| 8 | Configurar la autoridad de sellado de tiempo con su certificado (`IofeTimestampAuthority`), obtenido de su prestador | Sección 4.4 |
| 9 | Declarar una contingencia (`Contingency`) solo bajo un procedimiento aprobado por el INDECOPI, con su vigencia, y retirarla al terminar | Req. 14, 24 |
| 10 | Mantener sincronizado el reloj del sistema (NTP): la vigencia de certificados, CRL y TSL se evalúa contra él | Req. 12, 22 |
| 11 | Ejecutar la aplicación con una cuenta de servicio sin privilegios de administración y restringir el acceso al sistema que la aloja | Req. 14, 24 |
| 12 | Instalar los paquetes desde nuget.org y verificar su firma antes de desplegarlos (ver el manual de administración) | Req. 17, 27 |
