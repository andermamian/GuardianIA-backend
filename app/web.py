"""Sirve las interfaces web desde el mismo origen que la API.

Mismo origen = sin CORS, cookies SameSite=Strict funcionan y la CSP puede ser 'self'.
En producción puede ponerse la consola en otro subdominio con acceso restringido por VPN/IP;
el código no cambia porque todas las rutas son relativas.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


class _Static(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        # Revalidar siempre (ETag): tras desplegar, nadie se queda con un JS viejo que llama a una API nueva.
        response.headers["Cache-Control"] = "no-cache"
        return response


def install(app: FastAPI) -> None:
    if not WEB_DIR.exists():
        return
    app.mount("/static", _Static(directory=WEB_DIR), name="static")

    def page(name: str):
        def _serve():
            return FileResponse(WEB_DIR / name / "index.html", headers={"Cache-Control": "no-store"})
        return _serve

    @app.middleware("http")
    async def _raiz_al_navegador(request, call_next):
        # Un navegador que entra a la raíz espera la app, no el JSON de la API.
        # Los clientes de API (Accept: application/json) siguen recibiendo el JSON de siempre.
        if request.url.path == "/" and "text/html" in request.headers.get("accept", ""):
            # No se puede redirigir en el servidor conservando la sección: la parte después de «#»
            # nunca sale del navegador. Se devuelve una página mínima que completa el salto.
            return FileResponse(WEB_DIR / "shared" / "redirigir.html", headers={"Cache-Control": "no-store"})
        return await call_next(request)

    for name in ("app", "consola"):
        app.add_api_route(f"/{name}", lambda n=name: RedirectResponse(f"/{n}/"), include_in_schema=False)
        app.add_api_route(f"/{name}/", page(name), include_in_schema=False)

    # Página que el celular abre desde el QR para vincularse y reportar su ubicación (sin instalar app).
    def _vincular():
        return FileResponse(WEB_DIR / "app" / "vincular.html", headers={"Cache-Control": "no-store"})
    app.add_api_route("/vincular", _vincular, include_in_schema=False)

    # La CA local es pública (lo secreto es su clave, que nunca sale de data/certs/ca.key): se ofrece
    # también por HTTPS para reinstalarla o pasarla a otro equipo.
    def _ca():
        from app import tls
        ruta = tls.rutas().ca_crt
        if not ruta.is_file():
            from app.core.errors import not_found
            raise not_found("certificado")
        return FileResponse(ruta, media_type="application/x-x509-ca-cert", filename="GuardianIA-CA.crt",
                            headers={"Cache-Control": "no-store"})
    app.add_api_route("/ca.crt", _ca, include_in_schema=False)
    app.add_api_route("/app/vincular", _vincular, include_in_schema=False)
