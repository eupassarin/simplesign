# Cómo funciona

SimpleSign Agent es un programa pequeño que vive en la bandeja (la barra de menús, en macOS). Permite que una página web firme con un certificado que está **en esta computadora**: el almacén de certificados del sistema, un token criptográfico o una tarjeta inteligente.

La página nunca ve la clave privada. Envía los bytes a firmar y recibe la firma.

## El flujo

1. El servidor del sitio prepara el documento y calcula lo que hay que firmar.
2. La página llama al agente en `http://127.0.0.1:{port}`, en esta computadora.
3. El agente pide **su** confirmación, mostrando el sitio, el documento y el certificado. Con un token pide el PIN en su propia ventana.
4. La clave firma. Con un token, la firma se hace dentro del token.
5. La página envía la firma al servidor, que termina el documento firmado.

> Un navegador no puede acceder por sí solo a un token ni al almacén de certificados. El agente es el puente, y solo funciona para los sitios que usted autorice.

## Qué hay en esta ventana

| Sección | Para qué sirve |
| --- | --- |
| **Resumen** | Si el agente está activo y los certificados que encontró. |
| **Sitios** | Los sitios que usted autorizó o bloqueó. |
| **Actividad** | Lo que hizo el agente desde que inició. |
| **Probar** | Una prueba de extremo a extremo con su certificado real. |
| **Documentación** | Estas páginas. |

Configuración y Acerca de se abren con los iconos de la esquina superior derecha. Cerrar la ventana no detiene el agente: sigue en la bandeja hasta que elija **Salir** allí.

## A continuación

- ¿Recién llega? Lea [Primeros pasos](#start).
- ¿Está construyendo un sitio que firma? Lea [Integración](#integration).
- ¿Algo no funciona? Lea [Solución de problemas](#troubleshooting).
