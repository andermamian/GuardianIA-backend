# GuardianIA por HTTPS

Todo el proyecto funciona por HTTPS. Sin HTTPS el navegador del celular bloquea el GPS y la batería,
las cookies de sesión viajan sin protección y cualquiera en el mismo WiFi puede leer el tráfico.

## Arrancar

| Archivo | Qué hace |
|---|---|
| `INICIAR_GUARDIANIA.bat` | HTTPS en la red local: PC y celular. Abre el navegador en Dispositivos. |
| `INICIAR_SOLO_ESTE_PC.bat` | HTTPS solo en este PC; nadie de la red puede entrar. |
| `CONFIAR_CERTIFICADO.bat` | Instala la CA local en Windows para no ver "conexión no privada". |

Equivalentes en la terminal: `python -m app.servidor`, `python -m app.servidor --solo-local` y `python -m app.tls confiar`.

Direcciones:

- En el PC: `https://127.0.0.1:8443/app/`
- En el celular: `https://IP-del-PC:8443/app/` (la muestra el lanzador al arrancar)
- `http://…:8000` redirige solo a HTTPS, así que los marcadores y QR viejos siguen sirviendo.

> Ya no arranque con `uvicorn app.main:app` a mano: así no hay certificado ni redirección.

## Quitar el aviso "La conexión no es privada" (una sola vez)

GuardianIA crea su propia **autoridad certificadora (CA) local** la primera vez que arranca.

- **PC:** doble clic en `CONFIAR_CERTIFICADO.bat` y acepte el aviso de Windows. Luego cierre el
  navegador por completo. Chrome, Edge y Opera usan ese almacén; Firefox tiene el suyo (Ajustes →
  Privacidad → Certificados → Importar `data/certs/ca.crt`).
- **Celular Android:** abra `http://IP-del-PC:8000/certificado`, descargue el certificado e
  instálelo en Ajustes → Seguridad → Cifrado y credenciales → Instalar certificado → Certificado de CA.
  Compare la huella que muestra esa página con la de `python -m app.tls` en el PC.

Si prefiere no instalar nada, el aviso se puede aceptar a mano en cada navegador.

## Por qué es seguro instalar esta CA

- La CA está **restringida** (Name Constraints): solo puede firmar IP privadas (192.168.x, 10.x,
  172.16-31.x, 127.0.0.1) y `localhost`. Aunque alguien robara su clave, **no** serviría para
  suplantar google.com, el banco ni ningún sitio de internet: los navegadores lo rechazan.
- La clave privada vive solo en `data/certs/ca.key`, con permisos restringidos, y nunca se sirve
  por la red. `ca.crt` es público.
- Nunca suba `data/certs/` a GitHub (ya está cubierto por `.gitignore` si ignora `data/`).

## Cuando cambia la IP del PC

El lanzador lo detecta al arrancar y genera un certificado nuevo firmado por la **misma** CA. Los
equipos que ya confían en ella siguen sin avisos, pero el celular debe volver a vincularse, porque
la dirección cambió y el navegador guarda los datos por dirección.

## El agente de Windows

- Se conecta a `https://127.0.0.1:8443` y verifica el certificado **solo** contra la CA de
  GuardianIA (pinning). Un servidor con otro certificado es rechazado aunque Windows confíe en él.
- Los agentes registrados con `http://127.0.0.1:8000` migran solos la primera vez que arrancan.
- Si el agente corre en otro equipo, regístrelo con `--ca ruta\a\ca.crt`.

## Decisiones técnicas

- **Puertos separados (8443 HTTPS + 8000 redirección):** un proxy que atendiera ambos en el mismo
  puerto haría perder la IP real de cada cliente, que usan el límite de intentos y la auditoría.
- **Redirección 308:** a diferencia de 301/302, conserva el método (un POST sigue siendo POST).
- **Sin HSTS en local:** HSTS vuelve el aviso de certificado imposible de saltar, y los navegadores
  lo ignoran en direcciones IP. En producción, con un dominio y un certificado público, sí se envía
  (`GUARDIAN_ENV=production`).
