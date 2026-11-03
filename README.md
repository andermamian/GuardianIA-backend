# GuardianIA — API segura (v4)

Backend en Python (FastAPI) para la app Android **I.A-guardián**: antivirus con IA, protección antirrobo,
signos vitales desde relojes inteligentes, emergencias, bóveda cifrada, asistente con navegación web y VPN
inteligente. Dos puertas separadas: **usuario** (`/v1/auth`) y **consola administrativa** (`/v1/admin/auth`,
con 2FA obligatorio).

Autor del proyecto original: Anderson Mamián Chicangana.

## Arranque rápido

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m app.cli setup                                # crea el .env con claves nuevas
python -m app.cli create-admin admin@midominio.co "Nombre Apellido" super_admin
python -m app.cli enroll-mfa admin@midominio.co        # escanee con su app autenticadora
python -m app.servidor            # HTTPS (o doble clic en INICIAR_GUARDIANIA.bat)
```

¿Algo no funciona? `python -m app.cli doctor` revisa claves, base de datos, permisos de carpetas,
cifrado y firma de sesiones, y dice en español qué corregir.

```
```

Abra en Chrome o Edge:

- App del usuario: https://127.0.0.1:8443/app/
- Consola administrativa: https://127.0.0.1:8443/consola/
- Documentación de la API: https://127.0.0.1:8443/docs

Todo funciona por HTTPS con una CA local propia; `http://…:8000` redirige solo. Para no ver el aviso
de certificado: `CONFIAR_CERTIFICADO.bat`. Detalles en [docs/HTTPS.md](docs/HTTPS.md).

Pruebas: `pytest` (66 pruebas).

## Frontend web

Sin framework ni paso de compilación: JavaScript moderno (módulos ES) servido por el mismo FastAPI.
Se eligió así a propósito: no hay `node_modules` con cientos de dependencias de terceros que auditar,
funciona igual en Windows y Linux, y la CSP puede ser estricta (`script-src 'self'`, sin inline).

```
web/
├── shared/        base.css (sistema visual), dom.js (DOM sin innerHTML), api.js (sesión y errores),
│                  router.js, realtime.js (WebSocket), chart.js (SVG accesible), pulse.js (monitor)
├── app/           main.js, ble.js (reloj Bluetooth), vault-crypto.js (cifrado E2E),
│                  file-features.js (antivirus local), watch-session.js, components.js (SOS), views/
└── consola/       main.js (login con 2FA), views/
```

| Decisión | Por qué |
|---|---|
| Refresh token en cookie `HttpOnly` + `SameSite=Strict` + cabecera `X-Guardian-Web` | Un XSS no puede robar la sesión; otro sitio no puede usar la cookie (CSRF). El access token vive solo en memoria |
| Todo el texto del servidor entra con `textContent` | Un nombre de archivo como `<img onerror=...>` se muestra como texto (probado en E2E) |
| Contraseñas de la bóveda cifradas con Web Crypto (PBKDF2 600 000 + AES-256-GCM) | El servidor solo recibe texto cifrado; ni un administrador puede leerlas |
| El antivirus calcula hash, entropía y cadenas en el navegador | El archivo nunca se sube: privacidad y ancho de banda |
| Reloj por Web Bluetooth, perfil estándar Heart Rate (0x180D) con HRV (RMSSD) | Sin apps intermedias en relojes compatibles; la interfaz dice con honestidad cuáles no lo son |
| SOS con 2 s de presión sostenida; con teclado, confirmación | Evita activaciones en el bolsillo sin excluir a quien usa lector de pantalla |
| Fuentes del sistema, sin CDNs | Una app de salud no debe avisar a terceros cada vez que alguien la abre |
| Gracia de 20 s en la rotación del refresh token | Dos pestañas que renuevan a la vez no cierran la sesión; un token viejo usado después sí se trata como robo |

**Compatibilidad del reloj:** Chrome o Edge en Android, Windows, macOS o ChromeOS, desde `localhost` o HTTPS.
Safari (iPhone) y Firefox no implementan Web Bluetooth. Probar desde el celular en la red local requiere
HTTPS (por ejemplo `uvicorn ... --ssl-keyfile --ssl-certfile` con un certificado de `mkcert`).

## Pantallas Android → endpoints

| Interfaz (layout) | Módulo | Rutas principales |
|---|---|---|
| `activity_main` (login), `activity_admin_login` | `api/v1/auth.py` | `/v1/auth/*`, `/v1/admin/auth/*` |
| Contactos de emergencia, botón de pánico | `api/v1/emergency.py` | `/v1/emergency/*` |
| Monitoreo en tiempo real, reloj inteligente | `api/v1/health.py` | `/v1/wearables`, `/v1/vitals/*`, `/v1/health/*` |
| Emotional Bonding, Music Creator | `api/v1/health.py` | `/v1/wellbeing/*`, `/v1/music/*` |
| AI Security Hub, Vigilancia de Aplicaciones | `api/v1/antivirus.py` | `/v1/antivirus/*`, `/v1/apps/*` |
| Communication Hub, Personality Designer | `api/v1/assistant.py` | `/v1/assistant/*` |
| VPN (`VPNServerManager.kt`) | `api/v1/vpn.py` | `/v1/servers`, `/v1/recommend`, `/v1/ping` |
| `activity_guardian_antitheft_system` | `api/v1/devices.py` | `/v1/devices/*` |
| `activity_guardian_ai_vault_digital_seguro` | `api/v1/vault.py` | `/v1/vault/*` |
| Admin Dashboard, Emergency Command, System Diagnostics, Configuration Center, Users & Permissions | `api/v1/admin.py` | `/v1/admin/*` |
| Notificaciones en vivo | `main.py`, `api/v1/notifications.py` | WebSocket `/v1/ws` (usuario), `/v1/admin/ws` (personal), `/v1/notifications` |
| Sesión del navegador | `api/v1/web_auth.py` | `/v1/web/auth/*`, `/v1/web/admin/auth/*` |

### Agente antirrobo en el teléfono

El agente usa el `device_token` que devuelve `POST /v1/devices` (guárdelo en Android Keystore), no el JWT
del usuario: si cierran la sesión de la app, el equipo sigue reportando.

1. `POST /v1/devices/telemetry` cada 15 min (cada 30 s si está perdido); la respuesta dice cuándo reportar.
2. Si `comandos_pendientes > 0`: `POST /v1/devices/commands/pending`.
3. Ejecutar y responder `POST /v1/devices/commands/{id}/ack` devolviendo la `signature` recibida.

### Bóveda de contraseñas (cifrado de extremo a extremo)

El teléfono deriva la clave con Argon2id a partir de la contraseña maestra, cifra con AES-GCM y envía solo
el `ciphertext`. Para verificar filtraciones calcula el SHA-1 local y consulta
`/v1/vault/passwords/breach-range/{5 primeros caracteres}`.

## v4.1 — chats con archivos, skills y respuestas largas

- **VPN**: WARP se registra solo en modo auto, MTU 1280, verificación por `warp=on` del trazador de Cloudflare y motivos de fallo concretos (si no se puede, cae a Tor con aviso).
- **Chats**: los archivos que crea el asistente quedan guardados en el mensaje y reaparecen (con descarga) al reabrir el chat; los chats anteriores se recuperan desde la bitácora. Se listan todas las conversaciones y el modelo recibe lo más reciente de la conversación. Borrar un chat no borra los archivos de la Bóveda.
- **Skills** (`skills/*.md` integradas + propias por usuario, activar/desactivar, importar `.md`): programación avanzada, documentos Office, ciberseguridad defensiva, ingeniería de IA y respuestas extensas. Se aplican solo cuando vienen al caso y nunca anulan las reglas de seguridad. API: `/v1/assistant/skills`.
- **Sin estancamientos**: más tiempo de espera, más tokens, continuación automática si el modelo se corta, historial por presupuesto de caracteres y sin tope de 3 frases en «Detalle».
- **Documentos**: Word/PDF/Markdown con la extensión que cada trabajo necesita, automática (índice → capítulos → medición → ampliación). Requiere un modelo conectado; sin él solo hay plantilla. Si se pide un número menor de páginas, se respeta.
- **v4.1.2 — Tor y DNS:** con Tor activo, el proxy del sistema de Windows apunta a Tor (SOCKS5, DNS dentro de Tor) y se restaura al apagar; se desactiva con el ajuste `tor_proxy_sistema=false`. Con WARP/servidor se crea la regla NRPT «GuardianIA-VPN» que obliga a resolver todo por el DNS del túnel (se quita al desconectar; si quedara huérfana: `Get-DnsClientNrptRule | ? Comment -eq 'GuardianIA-VPN' | Remove-DnsClientNrptRule -Force`). Apps que no usan el proxy del sistema (otros clientes, algunos juegos) no pasan por Tor: para eso use Tor Browser.
- **v4.2 — velocidad y sandbox:** con modelo local el historial y las skills se recortan, los documentos se piden en una sola llamada y el aviso de «archivo listo» sale de una plantilla (antes eran 2-3 generaciones seguidas). El avance muestra etapa, palabras y segundos. **Sandbox** (`/v1/sandbox/*`, solo desde este equipo): botón «▶ Ejecutar» en los bloques Python/JavaScript del chat y diálogo «🧪 Sandbox», con la salida en vivo. Usa Docker si está instalado y la imagen (`python:3.12-slim`, `node:20-slim`) ya está descargada (sin red, memoria y CPU limitadas); si no, un proceso aparte con carpeta temporal, entorno limpio, tiempo/salida limitados y un guardián que bloquea red, subprocesos, borrados, escrituras ajenas y los datos de la app. Sin Docker NO es una caja a prueba de código malicioso.
- **v4.3 — extensión automática, pruebas y ZIP en el chat:** (1) ya no se exige «mínimo 50 páginas»: cada documento sale con la extensión que su trabajo necesita (una carta, 1 página; un manual, decenas; con un modelo en la nube el propio modelo decide el número, con uno local se estima por tipo de trabajo). Si pides un número de páginas se respeta, y `GUARDIAN_DOC_MIN_PAGINAS=50` devuelve el mínimo fijo. (2) **Probar código dentro del chat:** di «prueba este código» (o «ejecútalo») con un bloque Python/JavaScript —o sobre el último código de la conversación— y el asistente lo corre en el sandbox, muestra la salida en vivo, la deja guardada en el mensaje y, si falla, explica el error y propone la corrección. Solo desde este equipo. (3) **Organizar en ZIP:** «organiza estos trabajos en un zip» arma un proyecto con carpetas (`src/`, `tests/`…), README y requirements.txt; el código se coloca tal cual, sin reescribirlo, y las rutas peligrosas (`../`, absolutas) se descartan. Sin código en la conversación, el modelo genera el proyecto completo.
- **v4.4 — programar, pantalla de progreso y Office profesional:** (1) **Código con extensión automática:** el asistente escribe lo que la necesidad pida (una función o un proyecto entero). Si el código son 2 o más archivos, los organiza solo en un **ZIP** con carpetas y README (usa «# archivo: ruta» en la primera línea de cada bloque). Si pides un programa y estás en este equipo, lo **prueba en el sandbox** (proyecto completo, con sus módulos); si falla, el modelo recibe el error real y lo corrige (hasta 2 veces), mostrando cada versión. Los programas que piden teclado, abren ventana o levantan un servidor no se ejecutan solos. (2) **Pantalla de progreso** (estilo «computadora de Manus») dentro del mismo chat: cada paso (buscar, redactar, crear el archivo, probar, corregir, armar el ZIP) con su herramienta, argumentos, terminal en vivo y resultado, con línea de tiempo para revisar pasos anteriores y «Saltar al directo». (3) **Sandbox multilenguaje:** Python, JavaScript, TypeScript, Bash, PHP, Ruby, Perl, Lua, Go, Java, C, C++, Rust y C# (script) — los que estén instalados en el equipo; los compilados muestran la etapa «compilando» y sus errores. Solo Python tiene el guardián que bloquea red/borrados; el resto corre con límites de tiempo y salida (Docker aísla de verdad). (4) **Office más profesional:** paletas por tema (océano, esmeralda, atardecer, violeta, carbón, tierra), portada a color, encabezados con filete, tablas con bandas, recuadros «Nota/Consejo/Importante», negritas reales y números con formato en Word/PDF; presentaciones con portada, tarjetas, diapositivas de sección, cifras destacadas, citas, gráficos y cierre; Excel con encabezado, bandas, formatos de moneda y gráficos de color. Si el diseño falla, se usa el básico.
- La calidad final depende del modelo configurado: ningún parámetro hace a un modelo más capaz que el que lo ejecuta.

## Roles

| Permiso | supervisor | admin | super_admin |
|---|:-:|:-:|:-:|
| Dashboard, usuarios (ver), alertas (ver), incidentes | ✓ | ✓ | ✓ |
| Suspender usuarios, responder alertas, bloquear IP, alerta masiva, respaldos, decidir recomendaciones, umbrales clínicos | | ✓ | ✓ |
| Cambiar roles, rotar claves | | | ✓ |

## Producción

Use PostgreSQL, `GUARDIAN_ENV=production` (la app se niega a arrancar con secretos débiles), TLS en el
balanceador y `uvicorn --proxy-headers --forwarded-allow-ips=<IP del proxy>`. Detalles en
[`docs/SEGURIDAD.md`](docs/SEGURIDAD.md).

**Salud:** GuardianIA avisa y escala, pero no es un dispositivo médico certificado ni reemplaza la
valoración de un profesional. Ante una emergencia, llame al 123.

## v4.5 — El asistente lee cualquier archivo
- Adjuntos de hasta 4 GB (`GUARDIAN_ADJUNTO_MAX_MB`): se reciben por partes a disco temporal, nunca enteros en memoria.
- **ZIP / TAR / TGZ / GZ** (y ZIP dentro de ZIP): árbol de carpetas, resumen y contenido de cada archivo (código, Office, PDF, notebooks…) con su ruta; se omiten `.env`, claves, `node_modules`/`.git` y bombas de descompresión.
- **Fotos**: metadatos, OCR si hay motor y miniatura para modelos de visión (una foto sin texto ya no da error).
- **Videos**: duración, resolución, códecs, hasta 8 fotogramas repartidos y subtítulos incrustados (requiere `ffmpeg`). El audio no se transcribe.
- **Audio, ODT/EPUB, texto de cualquier extensión** y binarios desconocidos (se admiten diciendo con honestidad que no se pueden leer). `.7z`/`.rar`: convertir a ZIP.
