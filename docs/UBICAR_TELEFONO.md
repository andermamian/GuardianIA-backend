# Vincular y ubicar tu teléfono

Sin instalar ninguna app: todo pasa por el navegador del celular.

## Vincular (una sola vez)

1. En el PC, entra a **Dispositivos → Vincular equipo nuevo**. Aparece un código y un QR.
2. Con la **cámara del celular**, escanea el QR. Se abre una página web de GuardianIA.
3. Escribe un nombre para el teléfono y **acepta el permiso de ubicación**.
4. Listo: el teléfono queda vinculado a tu cuenta.

**Requisito:** el PC y el celular deben estar en el **mismo WiFi**. El QR usa la IP de tu PC en la red
(algo como `192.168.1.10:8000`), no `127.0.0.1`, porque para el celular «127.0.0.1» sería él mismo.

**Requisito 2: HTTPS.** Chrome solo entrega el GPS y la batería a páginas `https://`. Arranque
GuardianIA con **`INICIAR_GUARDIANIA.bat`**, que ya usa HTTPS: el QR apunta a `https://IP-del-PC:8443`.
Para no ver el aviso de certificado en el celular, instale la CA local desde
`http://IP-del-PC:8000/certificado` (detalles en [HTTPS.md](HTTPS.md)).

## Ubicar si se pierde

Desde el PC, en Dispositivos, sobre ese teléfono puedes:

- **Ver el mapa** con su última ubicación y el historial de las últimas 72 horas.
- **Sonar la alarma**, **bloquear**, **mostrar un mensaje** en pantalla o **borrar** (según el comando).
- Marcarlo como **perdido**: entonces reporta su ubicación cada 30 segundos y te avisa de cada cambio.

## Los límites reales de ubicar un teléfono (te lo digo con franqueza)

Hay muchas ideas sobre «rastrear un celular» que no son ciertas. Esto es lo que de verdad se puede y
lo que no:

| Método | ¿Lo puede hacer GuardianIA? | Realidad |
|---|---|---|
| **GPS por navegador** | **Sí** | Es lo que usa esta página. Preciso (5–20 m) y en tiempo real, mientras la pestaña esté abierta y el teléfono tenga señal e internet. |
| **GPS en segundo plano** | No | Requiere una app nativa instalada con permiso «siempre». Una página web solo ubica con la pestaña abierta. |
| **Por número de teléfono** | No | Nadie ubica un celular «con solo el número», salvo el operador con orden judicial. Quien lo ofrezca, engaña. |
| **Por IMEI** | No directamente | El IMEI sirve para que el **operador** o la **policía** bloqueen o rastreen el equipo. Tú no puedes rastrear por IMEI desde una app; sí puedes **denunciar el IMEI** para que lo bloqueen. |
| **Por antenas / red celular** | No | Solo el operador conoce a qué antena está conectado el teléfono. Se obtiene con denuncia formal. |

### Si te roban o pierdes el teléfono, lo que de verdad ayuda

1. **Marca el teléfono como perdido** en GuardianIA y revisa su última ubicación en el mapa.
2. **Denuncia** en la Policía: línea **123** o en `adenunciar.policia.gov.co`, y entrega la ubicación
   del historial. **No intentes recuperarlo tú mismo.**
3. **Bloquea el IMEI** ante tu operador (Claro, Movistar, Tigo, WOM). Así el equipo queda inservible
   en cualquier red de Colombia. El IMEI lo ves marcando `*#06#` (anótalo AHORA, mientras tienes el
   teléfono).
4. Cambia las contraseñas de tus cuentas importantes (correo, banco, redes) desde otro dispositivo.

GuardianIA te da la ubicación GPS real y el historial, que es la prueba más útil para la denuncia. El
bloqueo por IMEI y el rastreo por red son competencia del operador y la policía, no de una app.
