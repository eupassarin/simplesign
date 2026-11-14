# Solución de problemas

Empiece por **Probar**: muestra en qué paso falla. En **Acerca de** hay *Copiar diagnóstico* para enviarlo junto con una solicitud de soporte.

## El sitio dice que el agente no está instalado

- Compruebe el **Resumen**: el agente tiene que estar activo.
- Compruebe el puerto. El sitio tiene que llamar al mismo puerto en el que escucha el agente (`{port}` aquí, en Configuración).
- Algunas extensiones de navegador y herramientas de seguridad corporativas bloquean las llamadas a `127.0.0.1`. Pruebe otro navegador o una ventana privada.

## El agente no pudo iniciar: el puerto está en uso

Otro programa, u otra copia del agente, está usando el puerto `{port}`. Ciérrelo y pulse **Intentar de nuevo**, o elija otro puerto en Configuración. Si cambia el puerto, el sitio tiene que llamar al nuevo.

## Mi token o tarjeta inteligente no aparece

1. Conéctelo y pulse **Actualizar** en el **Resumen**.
2. Instale el controlador del token, del fabricante o de la autoridad de certificación que lo emitió. Sin el controlador la computadora no habla con el token.
3. **Acerca de** enumera los *Controladores PKCS#11* encontrados. Si el suyo no está ahí, el agente no sabe dónde está.
4. Para un controlador en un lugar poco habitual, defina la variable de entorno `SIMPLESIGN_PKCS11_LIBRARY` con la ruta completa de la biblioteca del controlador y abra el agente de nuevo.

## El sitio recibe "el marco de confianza no está habilitado"

Los filtros `country` y `trust`, y el antiguo `filterIcpBrasil`, solo responden por los marcos habilitados en Configuración, en **Marcos de confianza**. El error enumera los que están habilitados. Un listado sin filtro no se ve afectado.

En un DNIe peruano, el middleware que publica RENIEC (AuthentIC WebPack) es el que busca el agente; para otro token peruano cuyo módulo el agente no conoce, apunte `SIMPLESIGN_PKCS11_LIBRARY` a su biblioteca.

## El sitio recibe "no disponible sin conexión"

IOFE y eIDAS leen una lista de confianza por internet, la guardan en caché y la actualizan cada seis horas. Mientras no se puede leer, esos filtros responden 503 en lugar de devolver una lista más corta, y Configuración muestra *no disponible sin conexión*. Se vuelve a intentar un minuto después. Los marcos de Brasil llevan sus raíces dentro del agente y nunca necesitan la red para esto.

## Mi certificado del almacén del sistema no aparece

- Tiene que tener su clave privada en esta computadora. Un certificado copiado sin la clave no firma.
- Tiene que permitir la firma (uso de clave *firma digital* o *no repudio*).
- En macOS, el primer uso puede pedir permiso para usar la clave en el Llavero. Permítalo.

## El sitio rechaza mi certificado

El servidor del sitio comprueba el certificado antes de firmar. El **Resumen** marca los certificados que va a rechazar:

- **No sirve para firmar**: el uso de clave no permite ni *firma digital* ni *no repudio*.
- **Clave débil**: una clave RSA de menos de 2048 bits.

Use otro certificado, o pida uno nuevo a la autoridad de certificación. Un certificado cuya cadena venció también se
rechaza.

## El PIN es rechazado

El PIN es del token, no del agente. Después de algunos intentos incorrectos el token se bloquea, y solo la autoridad de certificación o la herramienta del propio token lo desbloquea. Deje de intentarlo y compruebe el PIN.

## El sitio no preguntó, o pregunta siempre

- Un sitio permitido con **Permitir** vuelve a preguntar después de que el agente se reinicia. Use **Permitir siempre** en los sitios que usa con frecuencia.
- Un sitio en la lista de **Bloqueados** se rechaza sin preguntar. Desbloquéelo en **Sitios**.

## La ventana de confirmación no aparece

Se abre por encima de las otras ventanas, pero puede estar en otra pantalla o escritorio. Busque las ventanas del agente, o responda a la solicitud pendiente antes de iniciar otra.

## macOS o Windows se niega a abrir la aplicación

Las descargas todavía no tienen firma de código. En macOS, pulse con el botón derecho en la aplicación y elija **Abrir** la primera vez. En Windows, elija **Más información** y **Ejecutar de todas formas**.
