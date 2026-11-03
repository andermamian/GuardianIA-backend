# GuardianIA en la nube (cuentas compartidas, sin el PC encendido)

El celular, la web y el PC usan **el mismo servidor y la misma base de datos**, que vive siempre encendida en internet.
Gratis: **Neon** (base de datos PostgreSQL) + **Render** (el servidor).

## 1. Base de datos (Neon, 3 minutos)
1. Entra a https://neon.tech, crea una cuenta y un proyecto.
2. Copia la **Connection string** (empieza por `postgresql://…`). Es tu `GUARDIAN_DATABASE_URL`.

## 2. Llaves (en el PC)
- **Si ya usas GuardianIA en el PC y quieres conservar tus cuentas:** usa los **mismos** `GUARDIAN_KEYRING` y
  `GUARDIAN_JWT_SECRET` que tienes en tu `.env`. Sin la misma llave, lo cifrado no se puede leer.
- **Si empiezas de cero:** `python -m app.cli generate-keys` y guarda las dos líneas.

## 3. Copiar tus cuentas del PC a la nube (solo si ya tienes cuentas)
```
python -m app.cli migrar-a-nube "postgresql://usuario:clave@host/base"
```
Copia usuarios, historial y ajustes. Se niega a escribir en una base que ya tenga datos.

## 4. Servidor (Render)
1. Sube esta carpeta a un repositorio de GitHub **privado** (el `.env` y la base local no se suben: están en `.dockerignore`/`.gitignore`).
2. En https://render.com: **New → Blueprint** → elige el repositorio (usa `render.yaml`).
3. Rellena las variables:

| Variable | Valor |
|---|---|
| `GUARDIAN_DATABASE_URL` | la cadena de Neon |
| `GUARDIAN_KEYRING` | `v1:…` (paso 2) |
| `GUARDIAN_JWT_SECRET` | el de tu `.env`, o déjalo que Render genere uno si empiezas de cero |
| `GUARDIAN_CORS_ORIGINS` | `https://TU-SERVICIO.onrender.com` |
| `GUARDIAN_ANTHROPIC_API_KEY` | tu clave de Claude (el asistente del servidor) |

4. Cuando termine, abre `https://TU-SERVICIO.onrender.com/health`: debe decir `"status":"ok"`.

## 5. La app de Android
En `local.properties` del proyecto Android añade:
```
servidor.url=https://TU-SERVICIO.onrender.com
```
Compila de nuevo: la app inicia sesión y crea cuentas contra ese servidor, sin buscar el PC.

## Lo que debes saber
- **Plan gratis de Render:** se duerme tras 15 min sin uso; la primera petición tarda ~50 s en despertar. Un plan de pago (~7 USD/mes) lo mantiene despierto.
- **Archivos de la bóveda** (documentos que crea el asistente del servidor): en el plan gratis el disco se borra en cada despliegue. Para conservarlos, añade un disco persistente en Render. Las cuentas y el historial NO se pierden: están en Neon.
- **Probado:** el servidor en modo producción con PostgreSQL, registro, inicio de sesión y la migración desde SQLite. **No probado:** la construcción del Docker y el despliegue en Render (no hay cómo hacerlo desde aquí).
- **Seguridad:** ahora tu servidor es público en internet. Contraseñas con Argon2, límite de intentos y 2FA ya vienen; usa contraseñas fuertes y no subas el `.env`.
