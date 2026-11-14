# Primeros pasos

## 1. Compruebe que el agente está activo

El **Resumen** muestra *El agente está activo* y la dirección en la que escucha. El icono de la bandeja dice lo mismo: lleno cuando está activo, solo el contorno cuando está en pausa.

## 2. Compruebe su certificado

Su certificado debe estar en la lista del **Resumen**:

- **Almacén del sistema**: certificados instalados en la computadora (el Llavero en macOS, el almacén personal en Windows).
- **Token o tarjeta inteligente**: conéctelo y pulse **Actualizar**. El controlador del token tiene que estar instalado.

Los certificados sin clave privada, o que no sirven para firmar, no aparecen.

## 3. Habilite su marco de confianza

En Configuración, **Marcos de confianza** enumera los que trae el agente: ICP-Brasil, Gov.br, IOFE (Perú) y eIDAS (Unión Europea). Habilite los que le interesen: solo esos responden a los filtros `country` y `trust` de la API y solo esos ponen un sello en un certificado del **Resumen**. IOFE y eIDAS leen una lista de confianza, que se descarga en segundo plano.

## 4. Haga la prueba

Abra **Probar** e inicie. Hace las mismas llamadas que hace un sitio y termina comprobando la firma. Si la prueba pasa, el agente, el certificado y la clave funcionan.

## 5. Firme en un sitio

La primera vez que un sitio llama al agente, usted responde si puede usar sus certificados:

- **Permitir**: por ahora, hasta que el agente se cierre.
- **Permitir siempre**: el sitio pasa a la lista de **Sitios** y no vuelve a preguntar.
- **Rechazar**: el sitio no recibe nada.

Después de eso, **cada firma** pide su confirmación, y el token pide el PIN.

> Confirme solo una firma que usted mismo haya iniciado en el sitio. Si aparece una confirmación de la nada, recházela.

## Bueno saber

- **Iniciar con el sistema** (Configuración) abre el agente en la bandeja cuando usted entra en la computadora.
- **Recordar el PIN del token** (Configuración) mantiene el token desbloqueado unos minutos, para que un lote de documentos no pida el PIN en cada uno. Lo normal es preguntar siempre.
- Puede quitar o bloquear un sitio en cualquier momento en **Sitios**.
