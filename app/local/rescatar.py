from __future__ import annotations
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
QTN = RAIZ / "data" / "local" / "cuarentena"


def descifrar(qtn: Path, destino: Path) -> None:
    import struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    clave = (QTN / ".clave").read_bytes()
    aes = AESGCM(clave)
    destino.parent.mkdir(parents=True, exist_ok=True)
    with open(qtn, "rb") as src, open(destino, "wb") as dst:
        if src.read(5) != b"GQTN2":
            raise ValueError("no es un archivo de cuarentena de GuardianIA")
        i = 0
        while cab := src.read(16):
            nonce, largo = cab[:12], struct.unpack("<I", cab[12:])[0]
            dst.write(aes.decrypt(nonce, src.read(largo), struct.pack("<Q", i)))
            i += 1


def rutas_desde_bd() -> dict:
    try:
        from app.db.models import QuarantineItem
        from app.db.session import SessionLocal
        db = SessionLocal()
        try:
            return {it.sha256: it.ruta_original for it in db.query(QuarantineItem).all() if it.ruta_original}
        finally:
            db.close()
    except Exception as e:
        print(f"(No pude leer la base de datos: {e}. Restauro por nombre.)")
        return {}


def main() -> int:
    solo = "--listar" in sys.argv
    archivos = sorted(QTN.glob("*.qtn"))
    if not archivos:
        print("No hay nada en cuarentena.")
        return 0
    rutas = rutas_desde_bd()
    print(f"Hay {len(archivos)} archivo(s) en cuarentena:\n")
    plan = []
    for q in archivos:
        sha = q.stem
        destino = Path(rutas.get(sha, str(RAIZ / f"RESCATADO_{sha[:12]}")))
        print(f"  {destino}")
        plan.append((q, destino))
    if solo:
        print("\n(Solo listado. Ejecute sin --listar para restaurar.)")
        return 0
    print("\nRestaurando...")
    ok = 0
    for q, destino in plan:
        try:
            if destino.exists():
                destino = destino.with_name(destino.stem + "_restaurado" + destino.suffix)
            descifrar(q, destino)
            q.unlink()
            ok += 1
        except Exception as e:
            print(f"  No se pudo restaurar {destino.name}: {e}")
    print(f"\nListo: {ok} de {len(plan)} restaurados. Vuelva a arrancar el servidor.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
