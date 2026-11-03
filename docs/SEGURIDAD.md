# Modelo de seguridad de GuardianIA

## Superficies y controles

| Superficie | Amenaza | Control |
|---|---|---|
| Login de la app | Fuerza bruta, relleno de credenciales | Argon2id, bloqueo progresivo, límite por IP y por correo, puntaje de riesgo del login |
| Consola admin | Robo de contraseña de un operador | Puerta separada (audiencia JWT distinta), 2FA TOTP obligatorio, tokens de 10 min |
| Escalada de privilegios | Admin que se sube el rol o suspende a un par | RBAC granular en código, `can_manage`, nadie se gestiona a sí mismo, siempre queda un super_admin |
| Tokens robados | Reuso de refresh token | Rotación con detección de reuso, hash con clave (HMAC) en BD, revocación al cambiar rol o contraseña |
| IDOR | Leer recursos de otro usuario cambiando el id | Toda consulta filtra por dueño; responde 404, no 403 |
| Bóveda (archivos) | Robo del disco o de un respaldo | AES-256-GCM, clave por archivo, AAD atado al dueño, nombre de archivo también cifrado |
| Bóveda (contraseñas) | Filtración total de la BD, operador curioso | Cifrado de extremo a extremo en el teléfono; el servidor solo guarda blobs |
| Subidas | Ejecutable disfrazado, SVG/HTML con JS | Tipo por firma de bytes con lista blanca, descarga como `attachment` + `nosniff` |
| Antirrobo | Ladrón que desvincula el equipo | No se elimina un dispositivo reportado; token propio del agente; borrado invalida el token |
| Comandos remotos | Comando alterado | Firma HMAC que el acuse debe devolver; vencimiento por tipo |
| Bitácora | Encubrir acciones editando la BD | Cadena SHA-256; `/v1/admin/audit/verify` y `python -m app.cli verify-audit` |
| Alerta masiva | Cuenta admin comprometida siembra pánico | Permiso propio, motivo obligatorio, 3 por hora |
| Datos de salud | Exposición de información sensible | Consentimiento explícito (Ley 1581 de 2012), la consola no ve series de signos vitales |

## Cliente web

| Amenaza | Control |
|---|---|
| XSS que roba la sesión | Refresh token en cookie HttpOnly; access token de 15 min solo en memoria; CSP `script-src 'self'` sin inline; DOM construido sin `innerHTML` |
| CSRF con la cookie | `SameSite=Strict`, ruta limitada a `/v1/web/...` y cabecera obligatoria `X-Guardian-Web` (fuerza verificación CORS previa) |
| Clickjacking | `frame-ancestors 'none'` |
| Filtración a terceros | Sin CDNs ni fuentes externas; `Referrer-Policy: no-referrer`; enlaces externos con `rel="noopener noreferrer"` |
| Enlaces maliciosos del asistente | Solo se aceptan `http`, `https` y `tel`; `javascript:` se convierte en `#` |
| Doble envío (dos SOS, dos borrados) | Botones deshabilitados mientras la petición está en curso |
| Borrado accidental | Acciones irreversibles piden escribir `BORRAR` |
| Clave de la bóveda expuesta | Se descarta al ocultar la pestaña o tras 5 min de inactividad; el portapapeles se limpia a los 30 s |

## Límite de tasa con varias réplicas

`core/ratelimit.py` guarda los contadores en memoria: con un solo proceso basta. Con varias réplicas
detrás de un balanceador, reemplace el almacén por Redis manteniendo la interfaz `hit(key, limit, window_s)`
(por ejemplo con `INCR` + `EXPIRE` o un sorted set para ventana deslizante).

## IP real detrás de un proxy

`client_ip` usa la IP de la conexión. Detrás de Nginx o un balanceador, ejecute
`uvicorn --proxy-headers --forwarded-allow-ips=<IP del proxy>`: así solo se confía en `X-Forwarded-For`
cuando lo reescribe su proxy, y un atacante no puede falsificarla para evadir bloqueos.

## Rotación de claves

1. Agregue `v2:<32 bytes base64>` a `GUARDIAN_KEYRING` y cambie `GUARDIAN_ACTIVE_KEY_VERSION=v2`.
2. Reinicie. Lo nuevo se cifra con v2 y lo viejo se sigue leyendo con v1.
3. Llame a `POST /v1/admin/keys/rotate` hasta que `pendientes` sea 0.
4. Retire `v1` del anillo.

## Lo que se eliminó del diseño original a propósito

- **"Encriptación cuántica"**: se reemplaza por AES-256-GCM verificable. El riesgo cuántico real está en el
  intercambio de claves y se resuelve con TLS 1.3 híbrido en el balanceador.
- **Reconocimiento facial, voz y perfil de "sospechosos"** en antirrobo: captura biometría de terceros sin
  consentimiento. La evidencia se entrega a la Policía.
- **Cifras decorativas** ("98.7% de precisión", "147 capturados"): el dashboard muestra métricas medidas.
