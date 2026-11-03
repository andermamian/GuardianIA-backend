"""Lector mínimo de ejecutables de Windows (formato PE), en Python puro.

El agente anterior no extraía las importaciones de los .exe, así que la capa heurística del motor
(«usa CreateRemoteThread», «usa SetWindowsHookEx»…) nunca recibía datos y no se disparaba. Este
módulo las extrae sin depender de pefile.

Todo está acotado: un ejecutable malicioso puede traer cabeceras corruptas a propósito para colgar
o tumbar al analizador. Por eso cada lectura valida límites y cada bucle tiene tope.
"""
from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field

MAX_DLLS = 128
MAX_FUNCIONES = 4000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


@dataclass
class Seccion:
    nombre: str
    entropia: float
    ejecutable: bool
    escribible: bool
    tamano_virtual: int
    tamano_crudo: int


@dataclass
class InfoPE:
    es_64: bool = False
    es_dll: bool = False
    importaciones: list[str] = field(default_factory=list)
    dlls: list[str] = field(default_factory=list)
    secciones: list[Seccion] = field(default_factory=list)
    tiene_certificado: bool = False
    punto_entrada_fuera: bool = False
    anomalias: list[str] = field(default_factory=list)


def entropia(datos: bytes) -> float:
    if not datos:
        return 0.0
    total = len(datos)
    return max(0.0, round(-sum((c / total) * math.log2(c / total) for c in Counter(datos).values()), 3))


def analizar(datos: bytes) -> InfoPE | None:
    """Devuelve la información del PE o None si no es un PE válido."""
    try:
        return _analizar(datos)
    except (struct.error, IndexError, ValueError, UnicodeDecodeError):
        return None


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _u64(d: bytes, o: int) -> int:
    return struct.unpack_from("<Q", d, o)[0]


def _cadena(d: bytes, o: int, maximo: int = 256) -> str:
    if o < 0 or o >= len(d):
        return ""
    fin = d.find(b"\x00", o, o + maximo)
    return d[o: fin if fin != -1 else o + maximo].decode("ascii", "replace")


def _analizar(d: bytes) -> InfoPE | None:
    if len(d) < 0x40 or d[:2] != b"MZ":
        return None
    pe = _u32(d, 0x3C)
    if pe <= 0 or pe + 24 > len(d) or d[pe:pe + 4] != b"PE\x00\x00":
        return None
    info = InfoPE()
    coff = pe + 4
    n_secciones = _u16(d, coff + 2)
    tam_opcional = _u16(d, coff + 16)
    caracteristicas = _u16(d, coff + 18)
    info.es_dll = bool(caracteristicas & 0x2000)
    opc = coff + 20
    magia = _u16(d, opc)
    if magia not in (0x10B, 0x20B):
        return None
    info.es_64 = magia == 0x20B
    punto_entrada = _u32(d, opc + 16)
    dirs = opc + (112 if info.es_64 else 96)
    n_dirs = min(_u32(d, dirs - 4), 16)

    def directorio(i: int) -> tuple[int, int]:
        if i >= n_dirs:
            return 0, 0
        return _u32(d, dirs + i * 8), _u32(d, dirs + i * 8 + 4)

    # ── secciones
    tabla = opc + tam_opcional
    if n_secciones > 96:
        info.anomalias.append(f"{n_secciones} secciones (anómalo)")
        n_secciones = 96
    rangos: list[tuple[int, int, int]] = []   # (va, tamaño, puntero crudo)
    en_seccion = False
    for i in range(n_secciones):
        s = tabla + i * 40
        if s + 40 > len(d):
            break
        nombre = d[s:s + 8].rstrip(b"\x00").decode("latin-1", "replace")
        v_tam, va, c_tam, c_ptr = _u32(d, s + 8), _u32(d, s + 12), _u32(d, s + 16), _u32(d, s + 20)
        flags = _u32(d, s + 36)
        muestra = d[c_ptr: c_ptr + min(c_tam, 262144)] if c_ptr < len(d) else b""
        sec = Seccion(nombre, entropia(muestra), bool(flags & IMAGE_SCN_MEM_EXECUTE),
                      bool(flags & IMAGE_SCN_MEM_WRITE), v_tam, c_tam)
        info.secciones.append(sec)
        rangos.append((va, max(v_tam, c_tam), c_ptr))
        if va <= punto_entrada < va + max(v_tam, c_tam):
            en_seccion = True
    info.punto_entrada_fuera = bool(punto_entrada) and not en_seccion and not info.es_dll

    def rva_a_offset(rva: int) -> int:
        for va, tam, ptr in rangos:
            if va <= rva < va + tam:
                return rva - va + ptr
        return -1

    # ── certificado (directorio 4: su «dirección» ya es un offset de archivo)
    cert_off, cert_tam = directorio(4)
    info.tiene_certificado = bool(cert_off and cert_tam and cert_off + 8 <= len(d) + cert_tam)

    # ── importaciones (directorio 1)
    imp_rva, imp_tam = directorio(1)
    off = rva_a_offset(imp_rva) if imp_rva else -1
    funciones = 0
    ancho = 8 if info.es_64 else 4
    bit_ordinal = 1 << 63 if info.es_64 else 1 << 31
    while off >= 0 and off + 20 <= len(d) and len(info.dlls) < MAX_DLLS:
        oft, _, _, nombre_rva, ft = struct.unpack_from("<IIIII", d, off)
        if not (oft or nombre_rva or ft):
            break
        dll = _cadena(d, rva_a_offset(nombre_rva)).lower()
        if dll:
            info.dlls.append(dll)
        thunk = rva_a_offset(oft or ft)
        while 0 <= thunk and thunk + ancho <= len(d) and funciones < MAX_FUNCIONES:
            valor = _u64(d, thunk) if info.es_64 else _u32(d, thunk)
            if not valor:
                break
            if not valor & bit_ordinal:
                nombre = _cadena(d, rva_a_offset(valor & 0x7FFFFFFF) + 2, 128)
                if nombre:
                    info.importaciones.append(nombre)
            funciones += 1
            thunk += ancho
        off += 20

    # ── rasgos típicos de empaquetadores y droppers
    nombres = {s.nombre.lower() for s in info.secciones}
    if nombres & {"upx0", "upx1", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", "mpress1", ".petite"}:
        info.anomalias.append("secciones de un empaquetador conocido (UPX, Themida, VMProtect…)")
    if any(s.ejecutable and s.escribible for s in info.secciones):
        info.anomalias.append("sección a la vez escribible y ejecutable (código que se modifica a sí mismo)")
    if info.punto_entrada_fuera:
        info.anomalias.append("el punto de entrada no está dentro de ninguna sección")
    if not info.importaciones and not info.es_dll and info.secciones:
        info.anomalias.append("no declara importaciones (típico de código empaquetado)")
    return info
