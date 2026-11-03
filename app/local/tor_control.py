"""Cliente mínimo del puerto de control de Tor (protocolo oficial «control-spec», texto por líneas).

Sirve para lo que un usuario necesita ver y hacer en vivo:

* **Circuito actual**: por qué 3 relevos pasa el tráfico y en qué país está el de salida.
* **Nueva identidad** (``SIGNAL NEWNYM``): circuitos nuevos; los sitios ven otra IP.
* **Avance del arranque** (``status/bootstrap-phase``).

Seguridad:
* Solo 127.0.0.1 (Tor abre el puerto de control SOLO en localhost; nunca en la red).
* Autenticación por cookie: Tor la escribe en su carpeta de datos privada; sin ella no se entra.
* Nada de texto libre hacia Tor: huellas (40 hex) e IPs se validan antes de enviarse, para que nadie
  pueda inyectar comandos en el protocolo (un salto de línea en un dato sería un comando nuevo).

Se escribe a mano (≈100 líneas) en lugar de depender de «stem»: el protocolo es sencillo y así no hay
una dependencia más que pueda no funcionar con versiones nuevas de Python.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path

PUERTO_CONTROL = 9051
_HUELLA = re.compile(r"^[0-9A-F]{40}$")


class ErrorControl(Exception):
    pass


class ControlTor:
    def __init__(self, cookie: Path, puerto: int = PUERTO_CONTROL, timeout: float = 5.0):
        self._s = socket.create_connection(("127.0.0.1", puerto), timeout=timeout)
        self._f = self._s.makefile("rb")
        try:
            clave = cookie.read_bytes().hex()
        except OSError as e:
            self.cerrar()
            raise ErrorControl("No encontré la cookie de control de Tor") from e
        self._comando(f"AUTHENTICATE {clave}")

    # ─────────────────────────── protocolo
    def _linea(self) -> str:
        l = self._f.readline()
        if not l:
            raise ErrorControl("Tor cerró la conexión de control")
        return l.decode("utf-8", "replace").rstrip("\r\n")

    def _comando(self, texto: str) -> list[str]:
        if "\r" in texto or "\n" in texto:
            raise ErrorControl("Comando inválido")             # nunca se inyectan líneas extra
        self._s.sendall((texto + "\r\n").encode("ascii"))
        salida: list[str] = []
        while True:
            l = self._linea()
            codigo, sep, resto = l[:3], l[3:4], l[4:]
            if not codigo.startswith("2"):
                raise ErrorControl(f"Tor respondió {l}")
            if sep == "+":                                       # bloque de datos hasta «.»
                salida.append(resto)
                while (d := self._linea()) != ".":
                    salida.append(d[1:] if d.startswith("..") else d)
            else:
                salida.append(resto)
                if sep == " ":
                    return salida

    def _info(self, clave: str) -> str:
        lineas = self._comando(f"GETINFO {clave}")
        texto = "\n".join(lineas)
        prefijo = f"{clave}="
        if texto.startswith(prefijo):
            texto = texto[len(prefijo):]
        return texto.removesuffix("\nOK").strip()

    # ─────────────────────────── lo que usa GuardianIA
    def nueva_identidad(self) -> None:
        self._comando("SIGNAL NEWNYM")

    def arranque(self) -> dict:
        t = self._info("status/bootstrap-phase")
        m = re.search(r"PROGRESS=(\d+)", t)
        s = re.search(r'SUMMARY="([^"]*)"', t)
        return {"porcentaje": int(m.group(1)) if m else 0, "resumen": s.group(1) if s else ""}

    def pais_de_ip(self, ip: str) -> str | None:
        ipaddress.ip_address(ip)                                 # valida: nada de texto libre
        p = self._info(f"ip-to-country/{ip}").strip().upper()
        return p if re.fullmatch(r"[A-Z]{2}", p) and p != "??" else None

    def relevo(self, huella: str) -> dict:
        if not _HUELLA.fullmatch(huella):
            raise ErrorControl("Huella de relevo inválida")
        ns = self._info(f"ns/id/{huella}")
        for l in ns.splitlines():
            if l.startswith("r "):
                partes = l.split()
                ip = partes[6] if len(partes) > 6 else None
                return {"nombre": partes[1], "ip": ip, "pais": self.pais_de_ip(ip) if ip else None}
        return {"nombre": None, "ip": None, "pais": None}

    def circuito_actual(self) -> list[dict]:
        """Relevos del circuito general construido más reciente: [entrada, medio, salida]."""
        ultimo = None
        for l in self._info("circuit-status").splitlines():
            partes = l.split()
            if len(partes) >= 3 and partes[1] == "BUILT" and "PURPOSE=GENERAL" in l:
                ultimo = partes[2]
        if not ultimo:
            return []
        relevos = []
        for salto in ultimo.split(","):
            huella = salto.lstrip("$").split("~")[0].split("=")[0]
            try:
                relevos.append(self.relevo(huella))
            except ErrorControl:
                relevos.append({"nombre": None, "ip": None, "pais": None})
        return relevos

    def cerrar(self) -> None:
        try:
            self._s.close()
        except OSError:
            pass
