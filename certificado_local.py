"""Compatibilidad: el manejo de certificados vive ahora en app/tls.py (CA local + certificado del
servidor). Este archivo se conserva para quien tenga el comando anterior en sus notas.

    python certificado_local.py          → python -m app.tls
    python certificado_local.py --nuevo  → python -m app.tls nuevo
"""
import sys

from app.tls import _main

if __name__ == "__main__":
    _main(["nuevo"] if "--nuevo" in sys.argv else sys.argv[1:])
