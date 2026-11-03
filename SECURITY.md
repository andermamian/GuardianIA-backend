# Seguridad y despliegue

Este repositorio público no contiene `.env`, contraseñas, tokens, claves privadas, bases de datos locales ni archivos de firma. Los valores sensibles deben configurarse como variables secretas en Render.

Variables mínimas para producción:

- `GUARDIAN_ENV=production`
- `GUARDIAN_JWT_SECRET`
- `GUARDIAN_KEYRING`
- `GUARDIAN_DATABASE_URL` (PostgreSQL)
- `GUARDIAN_CORS_ORIGINS`

No guardes valores reales en `render.yaml`, `.env.example`, issues ni commits.
