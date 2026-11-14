# Seguridad

## Qué garantiza el agente

- **La clave privada se queda aquí.** El agente devuelve firmas, nunca claves. En un token o una tarjeta inteligente la clave no puede salir del dispositivo.
- **Solo esta computadora habla con él.** Escucha en `127.0.0.1`, que otras máquinas de la red no pueden llamar.
- **Los sitios tienen que estar autorizados.** La primera llamada de un sitio le pregunta a usted. El sitio se reconoce por su origen exacto: `https://banco.example` y `https://banco.example:8443` son sitios distintos.
- **Cada firma se confirma.** La confirmación muestra el sitio, el nombre del documento y el certificado. Estar autorizado permite a un sitio listar certificados, no firmar por su cuenta.
- **El PIN nunca pasa por la página.** Usted lo escribe en la ventana del agente, o en el teclado del lector. Queda solo en memoria y, de forma predeterminada, no queda.
- **Límites.** Solicitudes de hasta 1 MB, 100 elementos por solicitud de firma, 20 llamadas por minuto y por sitio.
- **Solo se firman datos de firma.** Cada elemento tiene que ser atributos firmados CMS o un `SignedInfo` XML-DSig. Un resumen suelto, un documento o cualquier otra cosa se rechaza antes de preguntarle a usted.
- **El token avisa antes de bloquearse.** Cuando el token indica que se escribió un PIN incorrecto, la solicitud del PIN lo avisa, y en el último intento avisa de que un PIN incorrecto más bloquea la tarjeta.

## En una instalación gestionada

Hay dos opciones para un escenario en el que un servidor dirige el agente. Las dos están desactivadas hasta que alguien las active.

- **Solicitudes de firma firmadas por el servidor.** Con `signedRequestsRequired`, una firma se hace solo cuando la solicitud lleva un token firmado por una de las claves públicas configuradas. El token indica el sitio, el certificado y los bytes exactos a firmar, dura como máximo cinco minutos y se acepta una vez, así que una página no puede repetirlo ni pedir algo que el servidor no preparó. Lo que muestra la confirmación pasa a venir del token, no de la página.
- **Una lista fija de sitios.** Un administrador puede distribuir un `policy.json` que fija los sitios autorizados y las demás opciones. **Sitios** pasa entonces a mostrar la lista en modo lectura, un sitio desconocido se rechaza sin preguntarle, y la ventana indica qué opciones fijó su administrador.

## Qué debería hacer usted

- Confirme solo las firmas que usted inició. Una confirmación inesperada es motivo para rechazarla.
- Lea la dirección del sitio en la confirmación, no solo su nombre.
- Use **Permitir siempre** solo en los sitios que usa con frecuencia. Quite en **Sitios** los que ya no usa.
- Deje **Recordar el PIN del token** en *Nunca* en una computadora compartida.

## Qué no hace el agente

- No abre, no lee y no envía sus archivos. El sitio envía los bytes a firmar; el documento se queda con el sitio.
- No valida el contenido del documento. Lo que muestra la confirmación es lo que el sitio dice que está firmando.
- No envía nada a internet. Solo responde a llamadas hechas en esta computadora.

## Dónde quedan los datos

El archivo de configuración guarda el puerto, los sitios autorizados y bloqueados, los marcos de confianza que usted habilitó y sus opciones de idioma y tema. La lista de actividad queda en memoria y desaparece cuando el agente se cierra. No se guarda ningún certificado, clave, PIN ni documento.
