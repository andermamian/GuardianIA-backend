"""Arranque oficial de GuardianIA: siempre por HTTPS.

    python -m app.servidor                 red local (celular incluido) por https://<IP>:8443
    python -m app.servidor --solo-local    solo este PC (https://127.0.0.1:8443)
    python -m app.servidor --abrir         además abre el navegador

Qué hace:
1. Deja listos los certificados (app/tls.py): crea la CA local la primera vez y renueva el
   certificado del servidor si cambió la IP o está por vencer.
2. Sirve la app por HTTPS en el puerto 8443.
3. En el puerto 8000 (el de antes) atiende un servidor mínimo que SOLO:
   * redirige cualquier dirección http:// a la misma ruta en https://  → los marcadores y QR viejos
     siguen funcionando en vez de dar ERR_EMPTY_RESPONSE;
   * entrega la CA pública en http://<IP>:8000/ca.crt, para instalarla en el celular antes de que
     confíe en el HTTPS (la CA es pública: compartirla no expone nada; se verifica con la huella).
   Ese servidor no conoce la app, la base de datos ni ninguna sesión.

Por qué no HTTP y HTTPS en el mismo puerto: se puede con un proxy que «olfatee» el primer byte, pero
el servidor perdería la IP real de cada cliente, que usan el límite de intentos y la auditoría.
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import os
import socket
import sys
import threading
import webbrowser
from urllib.parse import quote

PUERTO_HTTPS = 8443
PUERTO_HTTP = 8000


# ──────────────────────────────────────────── servidor de redirección (ASGI, sin dependencias)
def app_redireccion(puerto_https: int, ca_crt, huella: str, hosts_validos: set[str]):
    """App ASGI mínima para el puerto HTTP. `hosts_validos` evita una redirección abierta: el
    encabezado Host lo escribe el cliente, así que solo se respeta si es una dirección de este PC."""

    def destino(host_hdr: str, ruta: str, query: str) -> str:
        host = host_hdr.rsplit(":", 1)[0] if host_hdr.count(":") == 1 else host_hdr
        if host.startswith("[") and "]" in host:           # IPv6 con corchetes
            host = host[: host.index("]") + 1]
        limpio = host.strip("[]").lower()
        if limpio not in hosts_validos:
            limpio = "127.0.0.1"
            host = limpio
        return f"https://{host}:{puerto_https}{quote(ruta, safe='/%:@!$&()*+,;=-._~')}" + (f"?{query}" if query else "")

    pagina = f"""<!doctype html><html lang="es-CO"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Certificado de GuardianIA</title>
<style>body{{font-family:system-ui,sans-serif;max-width:620px;margin:2rem auto;padding:0 1rem;line-height:1.5;
background:#0b1d2e;color:#eaf2fb}}a{{color:#38bdf8}}code{{word-break:break-all;background:#12263b;padding:.2rem .4rem;
border-radius:6px}}li{{margin:.4rem 0}}.btn{{display:inline-block;background:#38bdf8;color:#04121e;padding:.8rem 1.2rem;
border-radius:10px;font-weight:700;text-decoration:none}}</style></head><body>
<h1>Confiar en GuardianIA</h1>
<p>Instale este certificado una sola vez y el celular dejará de mostrar «conexión no privada».</p>
<p><a class="btn" href="/ca.crt">Descargar certificado (ca.crt)</a></p>
<h2>Android</h2><ol>
<li>Descargue el archivo con el botón de arriba.</li>
<li>Ajustes → Seguridad y privacidad → Más ajustes de seguridad → Cifrado y credenciales →
<b>Instalar un certificado → Certificado de CA</b> (en Xiaomi: Ajustes → Contraseñas y seguridad →
Privacidad → Cifrado y credenciales).</li>
<li>Elija <code>ca.crt</code> y confirme. Android avisará que la red puede ser supervisada: es el
aviso estándar al instalar cualquier CA propia.</li>
<li>Cierre Chrome por completo y vuelva a abrir GuardianIA.</li></ol>
<h2>Compruebe que es el certificado correcto</h2>
<p>En el PC, <code>python -m app.tls</code> muestra la huella. Debe coincidir con esta:</p>
<p><code>{html.escape(huella)}</code></p>
<p>Esta CA solo puede firmar direcciones de su red local (192.168.x, 10.x, 127.0.0.1…): no sirve para
suplantar ningún sitio de internet.</p>
<p><a href="{html.escape(f'https://127.0.0.1:{puerto_https}/app/')}">Ir a GuardianIA</a></p>
</body></html>""".encode()

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            # Hay que CONFIRMAR el arranque; si no, uvicorn (y cualquier cliente de pruebas) espera
            # para siempre. No hay nada que inicializar: se confirma de inmediato.
            while True:
                mensaje = await receive()
                if mensaje["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif mensaje["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        ruta = scope.get("path", "/")
        cabeceras = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        comunes = [(b"x-content-type-options", b"nosniff"), (b"cache-control", b"no-store")]
        if ruta == "/ca.crt":
            cuerpo = ca_crt.read_bytes()
            await send({"type": "http.response.start", "status": 200, "headers": comunes + [
                (b"content-type", b"application/x-x509-ca-cert"),
                (b"content-disposition", b'attachment; filename="GuardianIA-CA.crt"')]})
            await send({"type": "http.response.body", "body": cuerpo})
            return
        if ruta in ("/certificado", "/certificado/"):
            await send({"type": "http.response.start", "status": 200, "headers": comunes + [
                (b"content-type", b"text/html; charset=utf-8")]})
            await send({"type": "http.response.body", "body": pagina})
            return
        # 308 conserva el método y el cuerpo (un POST sigue siendo POST), a diferencia de 301/302.
        url = destino(cabeceras.get("host", "127.0.0.1"), ruta, scope.get("query_string", b"").decode("latin-1"))
        await send({"type": "http.response.start", "status": 308, "headers": comunes + [
            (b"location", url.encode("latin-1")), (b"content-type", b"text/plain; charset=utf-8")]})
        await send({"type": "http.response.body", "body": f"GuardianIA ahora usa HTTPS: {url}\n".encode()})

    return app


# ──────────────────────────────────────────────────────────────── arranque
def puerto_libre(host: str, puerto: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, puerto))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _explicar_puerto_ocupado(puerto: int) -> str:
    return (f"El puerto {puerto} está ocupado (probablemente GuardianIA ya corre en otra ventana).\n"
            f"  Ciérrelo con Ctrl+C en esa ventana, o desde PowerShell:\n"
            f"    netstat -ano | findstr :{puerto}\n"
            f"    taskkill /PID <número de la última columna> /F\n"
            f"  O use otro puerto: python -m app.servidor --puerto {puerto + 1000 if puerto < 64000 else 9443}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m app.servidor", description="Arranca GuardianIA por HTTPS.")
    p.add_argument("--solo-local", action="store_true", help="solo este PC (127.0.0.1); el celular no podrá entrar")
    p.add_argument("--puerto", type=int, default=PUERTO_HTTPS, help=f"puerto HTTPS (por defecto {PUERTO_HTTPS})")
    p.add_argument("--puerto-http", type=int, default=PUERTO_HTTP,
                   help=f"puerto que redirige http→https y entrega la CA (por defecto {PUERTO_HTTP}; 0 = no usar)")
    p.add_argument("--abrir", nargs="?", const="dispositivos", default=None, help="abre el navegador en esa sección")
    p.add_argument("--recargar", action="store_true", help="modo desarrollo: reinicia al cambiar el código")
    a = p.parse_args(argv)

    from app import tls
    host = "127.0.0.1" if a.solo_local else "0.0.0.0"
    rutas, hecho = tls.asegurar()
    ips = [ip for ip in tls.ips_locales() if ip != "127.0.0.1"]
    huella = tls.huella_ca()

    if not puerto_libre(host, a.puerto):
        sys.exit("✗ " + _explicar_puerto_ocupado(a.puerto))
    usar_http = a.puerto_http and puerto_libre(host, a.puerto_http)

    base_pc = f"https://127.0.0.1:{a.puerto}"
    # main.py lee esto para mostrar en el log la dirección real (antes decía http:// fijo).
    os.environ["GUARDIAN_URL_PUBLICA"] = base_pc
    print(f"\n  GuardianIA · HTTPS  ({hecho})")
    print(f"  En este PC:   {base_pc}/app/")
    if not a.solo_local:
        for ip in ips:
            print(f"  En la red:    https://{ip}:{a.puerto}/app/   (celular en el mismo WiFi)")
    if usar_http:
        print(f"  http://…:{a.puerto_http} redirige solo a HTTPS · certificado para el celular: "
              f"http://{ips[0] if ips and not a.solo_local else '127.0.0.1'}:{a.puerto_http}/certificado")
    elif a.puerto_http:
        print(f"  (aviso) El puerto {a.puerto_http} está ocupado: no habrá redirección desde http://")
    print(f"  Huella de la CA: {huella[:23]}…  ·  Quitar avisos del navegador: python -m app.tls confiar\n")

    import uvicorn

    if usar_http:
        hosts = {"127.0.0.1", "localhost", "::1", *ips}
        red = uvicorn.Server(uvicorn.Config(app_redireccion(a.puerto, rutas.ca_crt, huella, hosts),
                                            host=host, port=a.puerto_http, log_level="warning",
                                            access_log=False, lifespan="on"))
        # Sus mensajes informativos («Uvicorn running on http://…») harían creer que la app corre sin
        # cifrar: se silencian por hilo, sin tocar el log de la app principal. Los errores sí salen.
        import logging

        class _SoloErroresDelRedirector(logging.Filter):
            def filter(self, rec: logging.LogRecord) -> bool:
                return rec.threadName != "redireccion-http" or rec.levelno >= logging.WARNING

        for nombre in ("uvicorn.error", "uvicorn"):
            logging.getLogger(nombre).addFilter(_SoloErroresDelRedirector())
        # En un hilo aparte: uvicorn solo instala manejadores de Ctrl+C en el hilo principal, así que
        # al cerrar la app principal este hilo (daemon) termina con ella.
        threading.Thread(target=red.run, name="redireccion-http", daemon=True).start()

    if a.abrir:
        threading.Timer(3.0, lambda: webbrowser.open(f"{base_pc}/app/#/{a.abrir}")).start()

    uvicorn.run("app.main:app", host=host, port=a.puerto, ssl_keyfile=str(rutas.key),
                ssl_certfile=str(rutas.crt), reload=a.recargar, proxy_headers=False,
                reload_dirs=["app"] if a.recargar else None)


if __name__ == "__main__":
    main()
