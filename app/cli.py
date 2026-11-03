"""Herramientas de operación (se ejecutan en el servidor, nunca expuestas por HTTP).

    python -m app.cli setup                         # crea el .env con claves nuevas (empiece por aquí)
    python -m app.cli doctor                        # revisa la instalación y dice qué falta
    python -m app.cli doctor --registro             # además prueba un registro real y muestra el error exacto
    python -m app.cli generate-keys                 # secretos para el archivo .env
    python -m app.cli migrar-a-nube "postgresql://…" # copia las cuentas del PC a la base de la nube
    python -m app.cli create-admin correo@x.co "Nombre" super_admin
    python -m app.cli enroll-mfa correo@x.co        # 2FA obligatorio para entrar a la consola
    python -m app.cli entrenar antivirus|vitales|intencion   # entrena las redes neuronales
    python -m app.cli vpn-servidor                  # registra un servidor WireGuard REAL (con tunel)
    python -m app.cli sembrar-vpn                   # carga servidores VPN de ejemplo para probar la recomendación
    python -m app.cli instalar-lectura              # instala los lectores de PDF, Word, Excel, PowerPoint e imágenes
    python -m app.cli usar-ollama                   # conecta un modelo local (gratis, sin clave)
    python -m app.cli probar-ia                     # comprueba la conexión con el modelo avanzado
    python -m app.cli verify-audit                  # comprueba la cadena de la bitácora

Por qué no hay endpoint para crear el primer administrador: cualquier «instalador web» expuesto
es la puerta que un atacante prueba primero. El primer super_admin se crea con acceso a la
máquina, que ya implica control total.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import os
import secrets
import subprocess
import sys

from pathlib import Path

from sqlalchemy import func, select

from app.core import audit, rbac
from app.core.crypto import open_text, seal_text
from app.core.security import (hash_password, utcnow, new_totp_secret, password_problems, recovery_codes, token_hash,
                               totp_uri, verify_totp)
from app.db.models import User
from app.db.session import SessionLocal, init_db
from app.services.auth import email_norm


def _require_keys() -> None:
    """El CLI NO genera claves temporales a propósito: si cifrara el secreto 2FA con una clave que
    el servidor no tiene, el administrador quedaría sin poder entrar y sin explicación."""
    from app.core.config import get_settings
    s = get_settings()
    problems = []
    if len(s.jwt_secret) < 48:
        problems.append("GUARDIAN_JWT_SECRET")
    try:
        if s.active_key_version not in s.keys():
            problems.append("GUARDIAN_KEYRING")
    except ValueError:
        problems.append("GUARDIAN_KEYRING")
    if problems:
        _fail(f"Falta {' y '.join(problems)} en el archivo .env.\n"
              "  Ejecute:  python -m app.cli generate-keys\n"
              "  y pegue el resultado en .env antes de continuar.")


def _fail(msg: str) -> None:
    print(f"✗ {msg}", file=sys.stderr)
    sys.exit(1)


def migrar_a_nube(args: argparse.Namespace) -> None:
    """Copia TODAS las cuentas y datos de este servidor (SQLite del PC) a una base PostgreSQL en la nube.

    Importante: en la nube hay que usar el MISMO GUARDIAN_KEYRING y GUARDIAN_JWT_SECRET que tiene el .env del PC;
    los datos sensibles van cifrados con esa llave y, sin ella, no se podrían leer.
    """
    import importlib

    from sqlalchemy import create_engine, func, select, text

    from app.core.config import get_settings
    from app.db.session import Base, engine as origen

    url = args.url
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    if not get_settings().database_url.startswith("sqlite"):
        _fail("Este comando se ejecuta en el PC, donde la base actual es SQLite.")
    importlib.import_module("app.db.models")
    destino = create_engine(url, pool_pre_ping=True, future=True)
    Base.metadata.create_all(destino)
    copiadas = {}
    with origen.connect() as o, destino.begin() as d:
        for tabla in Base.metadata.sorted_tables:
            if d.execute(select(func.count()).select_from(tabla)).scalar():
                _fail(f"La tabla «{tabla.name}» de la nube ya tiene datos. Use una base vacía para no mezclar cuentas.")
        for tabla in Base.metadata.sorted_tables:
            filas = [dict(r._mapping) for r in o.execute(select(tabla))]
            for i in range(0, len(filas), 500):
                d.execute(tabla.insert(), filas[i:i + 500])
            copiadas[tabla.name] = len(filas)
    for nombre, n in copiadas.items():
        if n:
            print(f"  {nombre}: {n}")
    print(f"✓ Listo: {sum(copiadas.values())} filas copiadas a la nube.")
    print("  Recuerde usar en la nube el mismo GUARDIAN_KEYRING y GUARDIAN_JWT_SECRET de su .env.")


def generate_keys(_: argparse.Namespace) -> None:
    print("# Pegue esto en .env (o en el gestor de secretos). No lo suba a Git.")
    print(f"GUARDIAN_JWT_SECRET={secrets.token_urlsafe(48)}")
    print(f"GUARDIAN_KEYRING=v1:{base64.b64encode(os.urandom(32)).decode()}")
    print("GUARDIAN_ACTIVE_KEY_VERSION=v1")


def setup(args: argparse.Namespace) -> None:
    """Deja el proyecto listo para arrancar: crea .env con claves nuevas si no existe."""
    from app.core.config import PROJECT_ROOT
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists() and not args.force:
        print(f"Ya existe {env_path}. Use --force para reemplazarlo (perdería acceso a lo ya cifrado).")
        return doctor(args)
    env_path.write_text(
        "GUARDIAN_ENV=development\n"
        f"GUARDIAN_JWT_SECRET={secrets.token_urlsafe(48)}\n"
        f"GUARDIAN_KEYRING=v1:{base64.b64encode(os.urandom(32)).decode()}\n"
        "GUARDIAN_ACTIVE_KEY_VERSION=v1\n"
        "GUARDIAN_DATABASE_URL=sqlite:///./guardian.db\n"
        "GUARDIAN_VAULT_DIR=./data/vault\n"
        "GUARDIAN_BACKUP_DIR=./data/backups\n",
        encoding="utf-8")
    try:
        os.chmod(env_path, 0o600)  # en Linux/Mac; en Windows no aplica
    except OSError:
        pass
    print(f"✓ Creado {env_path} con claves nuevas. No lo suba a Git (ya está en .gitignore).")
    print("  Siguiente paso:  uvicorn app.main:app --reload")


def doctor(args: argparse.Namespace) -> None:
    """Revisa la instalación y explica en español qué falta. No cambia nada."""
    from app.core.config import get_settings
    s = get_settings()
    ok = True

    def check(titulo: str, bien: bool, ayuda: str = "") -> None:
        nonlocal ok
        print(f"{'✓' if bien else '✗'} {titulo}")
        if not bien:
            ok = False
            if ayuda:
                print(f"    → {ayuda}")

    env_file = s.env_file_in_use()
    check(f"Archivo .env: {env_file or 'no encontrado'}", env_file is not None,
          "Ejecute: python -m app.cli setup")
    check("GUARDIAN_JWT_SECRET configurado (firma las sesiones)", len(s.jwt_secret) >= 48,
          "Falta o es corto. Ejecute: python -m app.cli setup  (o generate-keys y péguelo en .env)")
    try:
        keys_ok = s.active_key_version in s.keys()
        detalle = f"versión activa {s.active_key_version}, {len(s.keys())} clave(s)"
    except ValueError as e:
        keys_ok, detalle = False, str(e)
    check(f"GUARDIAN_KEYRING para cifrar datos ({detalle})", keys_ok,
          "Falta la clave activa. Ejecute: python -m app.cli setup")

    try:
        init_db()
        db = SessionLocal()
        try:
            total = db.execute(select(func.count()).select_from(User)).scalar_one()
            staff = db.execute(select(func.count()).select_from(User).where(User.role != "user")).scalar_one()
            mfa = db.execute(select(func.count()).select_from(User).where(
                User.role != "user", User.totp_enabled.is_(True))).scalar_one()
        finally:
            db.close()
        check(f"Base de datos accesible ({s.database_url})", True)
        check(f"Cuentas de usuario: {total - staff}", True)
        check(f"Administradores con 2FA activo: {mfa} de {staff}", staff == 0 or mfa == staff,
              "Ejecute: python -m app.cli enroll-mfa <correo>  (sin 2FA no se entra a la consola)")
        if staff == 0:
            print("    → Aún no hay administradores. Cree uno:")
            print("      python -m app.cli create-admin correo@midominio.co \"Nombre Apellido\" super_admin")
    except Exception as e:  # noqa: BLE001
        check(f"Base de datos accesible ({s.database_url})", False, f"{type(e).__name__}: {e}")

    for nombre, ruta in (("bóveda", s.vault_dir), ("respaldos", s.backup_dir)):
        path = Path(ruta)
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".escritura"
            probe.write_text("ok")
            probe.unlink()
            check(f"Carpeta de {nombre} escribible ({path})", True)
        except OSError as e:
            check(f"Carpeta de {nombre} escribible ({path})", False, str(e))

    faltantes = []
    for modulo, para in [("pypdf", "PDF"), ("docx", "Word"), ("openpyxl", "Excel"), ("pptx", "PowerPoint")]:
        try:
            __import__(modulo)
        except ImportError:
            faltantes.append(para)
    check("Lectura de archivos adjuntos (PDF, Word, Excel, PowerPoint)", not faltantes,
          f"Falta el lector de {', '.join(faltantes)}. Ejecute: python -m app.cli instalar-lectura"
          if faltantes else "")
    try:
        import pytesseract
        ocr_ok = bool(pytesseract.get_languages(config=""))
    except Exception:  # noqa: BLE001
        ocr_ok = False
    check("OCR para leer texto en imágenes", ocr_ok,
          "Opcional. Instale Tesseract (https://github.com/UB-Mannheim/tesseract/wiki) con el idioma español")

    from app.core.tz import available as tz_available
    check(f"Asistente conectado a un modelo avanzado ({s.llm_kind})", s.llm_kind != "ninguno",
          "Sin modelo el asistente responde en modo local. Ejecute: python -m app.cli probar-ia")
    check(f"Navegación web del asistente {'activada' if s.web_browsing_enabled else 'desactivada'}",
          s.web_browsing_enabled, "Actívela con GUARDIAN_WEB_BROWSING_ENABLED=true en el .env")

    check(f"Zona horaria '{s.timezone}' disponible", tz_available(s.timezone),
          "Falta la base de zonas horarias (normal en Windows). Ejecute:  pip install tzdata\n"
          "      Sin ella el servicio sigue funcionando, pero usa UTC para el análisis de accesos.")

    try:
        from app.core.crypto import open_text, seal_text
        check("Cifrado funcionando", open_text(seal_text("prueba", "doctor"), "doctor") == "prueba")
        from app.core.security import create_access_token
        check("Firma de sesiones funcionando", bool(create_access_token(
            subject="diagnostico", audience="guardianai:app", role="user", session_id="x", minutes=1)))
    except Exception as e:  # noqa: BLE001
        check("Cifrado y firma de sesiones", False, f"{type(e).__name__}: {e}. Revise las claves del .env")

    print(f"  Hora del servidor: {utcnow().astimezone().strftime('%d/%m/%Y %H:%M:%S %Z')}")
    print("    (si un código 2FA correcto se rechaza, es que esta hora no coincide con la de su celular:")
    print("     en Windows, Configuración → Hora e idioma → Sincronizar ahora)")

    if getattr(args, "registro", False):
        ok = _probar_registro() and ok

    print()
    print("Todo listo. Arranque con: uvicorn app.main:app --reload" if ok
          else "Corrija lo marcado con ✗ y vuelva a ejecutar: python -m app.cli doctor")
    if not ok:
        sys.exit(1)


def _probar_registro() -> bool:
    """Crea y borra una cuenta de prueba llamando a la API de verdad.

    Si falla, imprime la traza completa: es la forma más rápida de ver la causa real de un
    «Error interno» sin tener que leer el log del servidor.
    """
    import traceback as tb

    from fastapi.testclient import TestClient

    from app.main import app
    correo = f"prueba-{secrets.token_hex(4)}@example.com"
    print("\nProbando un registro real...")
    try:
        with TestClient(app, raise_server_exceptions=True) as client:
            r = client.post("/v1/auth/register", json={
                "email": correo, "full_name": "Cuenta De Prueba",
                "password": "Zorro montaña bicicleta 4471", "accept_terms": True, "accept_health_data": True})
    except Exception:  # noqa: BLE001
        print("✗ El registro falló. Causa real:\n")
        tb.print_exc()
        return False
    if r.status_code == 201:
        db = SessionLocal()
        try:
            u = db.execute(select(User).where(User.email == correo)).scalar()
            if u:
                db.delete(u)
                db.commit()
        finally:
            db.close()
        print("✓ Registro correcto (la cuenta de prueba se borró)")
        return True
    print(f"✗ El registro respondió {r.status_code}: {r.text[:500]}")
    return False


def create_admin(args: argparse.Namespace) -> None:
    _require_keys()
    if args.role not in rbac.STAFF_ROLES:
        _fail(f"Rol inválido. Use: {', '.join(rbac.STAFF_ROLES)}")
    init_db()
    db = SessionLocal()
    try:
        email = email_norm(args.email)
        if db.execute(select(User).where(User.email == email)).scalar():
            _fail("Ya existe una cuenta con ese correo")
        pw = getpass.getpass("Contraseña (no se muestra): ")
        if pw != getpass.getpass("Repita la contraseña: "):
            _fail("Las contraseñas no coinciden")
        if problems := password_problems(pw, email=email, name=args.name):
            _fail("Contraseña rechazada: " + "; ".join(problems))
        u = User(email=email, full_name=args.name, password_hash=hash_password(pw), role=args.role)
        db.add(u)
        db.flush()
        audit.record(db, "cli.admin_created", target_type="user", target_id=u.id, level="security",
                     detail={"rol": args.role}, commit=False)
        db.commit()
        print(f"✓ Cuenta {args.role} creada. Siguiente paso obligatorio: python -m app.cli enroll-mfa {email}")
    finally:
        db.close()


def enroll_mfa(args: argparse.Namespace) -> None:
    _require_keys()
    init_db()
    db = SessionLocal()
    try:
        u = db.execute(select(User).where(User.email == email_norm(args.email))).scalar()
        if u is None:
            _fail("No existe esa cuenta")
        if u.totp_enabled and not args.reset:
            _fail("La cuenta ya tiene 2FA. Use --reset para reemplazarlo (invalida el anterior)")
        secret = new_totp_secret()
        print("\nAgregue esta cuenta en su app autenticadora (Aegis, Google Authenticator, 1Password):")
        print(f"  URI:    {totp_uri(secret, u.email)}")
        print(f"  Clave:  {secret}\n")
        code = input("Escriba el código de 6 dígitos que muestra la app: ").strip()
        if not verify_totp(secret, code):
            _fail("Código incorrecto; no se guardó nada")
        codes = recovery_codes()
        u.totp_secret_enc = seal_text(secret, f"totp:{u.id}")
        assert open_text(u.totp_secret_enc, f"totp:{u.id}") == secret
        u.totp_enabled, u.recovery_code_hashes = True, [token_hash(c) for c in codes]
        audit.record(db, "cli.mfa_enrolled", actor_id=u.id, target_type="user", target_id=u.id, level="security",
                     detail={"reemplazo": bool(args.reset)}, commit=False)
        db.commit()
        print("\n✓ 2FA activado. Códigos de recuperación (úselos una sola vez; guárdelos fuera de este equipo):")
        for c in codes:
            print(f"   {c}")
    finally:
        db.close()


PAQUETES_LECTURA = ["pypdf", "python-docx", "openpyxl", "python-pptx", "Pillow", "pytesseract",
                    "reportlab", "matplotlib", "qrcode", "MIDIUtil"]


SERVIDORES_EJEMPLO = [
    # id, país, ciudad, host, puerto, protocolo, premium, carga, latencia anunciada
    ("co-bog-1", "CO", "Bogotá", "bog1.vpn.guardianai.dev", 51820, "wireguard", False, 0.35, 18),
    ("co-mde-1", "CO", "Medellín", "mde1.vpn.guardianai.dev", 51820, "wireguard", False, 0.52, 24),
    ("us-mia-1", "US", "Miami", "mia1.vpn.guardianai.dev", 51820, "wireguard", False, 0.61, 62),
    ("us-nyc-1", "US", "Nueva York", "nyc1.vpn.guardianai.dev", 443, "openvpn", True, 0.44, 88),
    ("mx-mex-1", "MX", "Ciudad de México", "mex1.vpn.guardianai.dev", 51820, "wireguard", False, 0.48, 71),
    ("br-sao-1", "BR", "São Paulo", "sao1.vpn.guardianai.dev", 51820, "wireguard", True, 0.29, 95),
    ("es-mad-1", "ES", "Madrid", "mad1.vpn.guardianai.dev", 51820, "wireguard", True, 0.38, 140),
    ("ch-zrh-1", "CH", "Zúrich", "zrh1.vpn.guardianai.dev", 51820, "wireguard", True, 0.22, 165),
    ("se-sto-1", "SE", "Estocolmo", "sto1.vpn.guardianai.dev", 51820, "wireguard", True, 0.31, 172),
    ("de-fra-1", "DE", "Fráncfort", "fra1.vpn.guardianai.dev", 443, "openvpn", False, 0.67, 158),
]


def entrenar(args: argparse.Namespace) -> None:
    """Entrena una red neuronal con los datos de este despliegue."""
    from app.ml import asistente as ml_asistente
    from app.ml.entrenamiento import (DatosInsuficientes, carpeta_modelos, entrenar_antivirus,
                                      entrenar_vitales, limpiar_cache)
    init_db()

    def avance(epoca: int, perdida: float) -> None:
        print(f"  época {epoca:>4} · pérdida {perdida:.5f}")

    db = SessionLocal()
    try:
        print(f"Entrenando «{args.modelo}» …")
        if args.modelo == "intencion":
            red, metricas, ruta = ml_asistente.entrenar(carpeta_modelos(), epocas=args.epocas)
            importancia = []
            nota = f"{len(ml_asistente.INTENCIONES)} intenciones, corpus semilla con aumento de datos"
        else:
            constructor = entrenar_antivirus if args.modelo == "antivirus" else entrenar_vitales
            try:
                resultado = constructor(db, epocas=args.epocas, registro=avance)
            except DatosInsuficientes as e:
                _fail(str(e))
            metricas, ruta, importancia, nota = (resultado.metricas, resultado.ruta,
                                                 resultado.importancia, resultado.nota)
    finally:
        db.close()

    limpiar_cache()
    print(f"\n✓ Modelo guardado en {ruta}")
    print(f"  {nota}")
    m = metricas.to_dict()
    print(f"  Ejemplos: {m['ejemplos_entrenamiento']} entrenamiento · {m['ejemplos_validacion']} validación")
    print(f"  Épocas: {m['epocas']} · pérdida final {m['perdida_final']}")
    if args.modelo == "vitales":
        print(f"  Umbral de anomalía: {m['umbral']}")
    else:
        print(f"  Exactitud {m['exactitud']:.1%} · precisión {m['precision']:.1%} · "
              f"sensibilidad {m['sensibilidad']:.1%} · F1 {m['f1']:.1%}")
        if m.get("auc"):
            print(f"  AUC {m['auc']:.3f}")
        if m.get("matriz"):
            print(f"  Matriz de confusión: {m['matriz']}")
    if importancia:
        print("  Rasgos más influyentes: " + ", ".join(f"{n} ({v:.0%})" for n, v in importancia[:5]))
    print("\n  El modelo se usa automáticamente en el próximo análisis. Reentrene cuando acumule más datos.")


def vpn_servidor(args: argparse.Namespace) -> None:
    """Registra un servidor WireGuard real, el que sí levanta túnel.

    Los servidores de «sembrar-vpn» son de ejemplo y no tienen nada detrás: sirven para demostrar la
    recomendación, no para cifrar tráfico. Este comando registra uno de verdad, con su clave pública,
    su endpoint y la IP por la que sale el tráfico (que es lo que permite verificar el túnel).
    """
    from app.db.models import VpnServer
    init_db()
    db = SessionLocal()
    try:
        servidor = db.get(VpnServer, args.id) or VpnServer(id=args.id)
        servidor.country, servidor.city = args.pais.upper()[:2], args.ciudad
        servidor.host, servidor.port = args.endpoint.rsplit(":", 1)[0], int(args.endpoint.rsplit(":", 1)[1])
        servidor.protocol, servidor.active, servidor.is_premium = "wireguard", True, args.premium
        servidor.public_key, servidor.endpoint = args.clave_publica, args.endpoint
        servidor.ip_salida = args.ip_salida or args.endpoint.rsplit(":", 1)[0]
        servidor.subred, servidor.dns = args.subred, args.dns
        db.merge(servidor)
        db.commit()
        print(f"✓ Servidor «{args.ciudad}» registrado con túnel real")
        print(f"  Endpoint:   {servidor.endpoint}")
        print(f"  IP salida:  {servidor.ip_salida}  (con esta se verifica que el túnel funciona)")
        print(f"  Subred:     {servidor.subred}")
        print("\n  En el servidor WireGuard debe agregar cada dispositivo como [Peer] con la clave")
        print("  pública que muestra:  python guardian_agent.py vpn estado")
    finally:
        db.close()


def sembrar_vpn(args: argparse.Namespace) -> None:
    """Carga servidores de ejemplo para poder probar y demostrar la recomendación de la IA.

    Son direcciones de ejemplo, no servidores reales: sirven para que el motor tenga con qué comparar.
    En producción se cargan los servidores propios (o los del proveedor contratado) desde la consola.
    """
    from app.db.models import VpnServer
    init_db()
    db = SessionLocal()
    try:
        nuevos = 0
        for id_, pais, ciudad, host, puerto, protocolo, premium, carga, latencia in SERVIDORES_EJEMPLO:
            if db.get(VpnServer, id_):
                continue
            db.add(VpnServer(id=id_, country=pais, city=ciudad, host=host, port=puerto, protocol=protocolo,
                             is_premium=premium, load=carga, latency_ms=latencia, active=True))
            nuevos += 1
        db.commit()
        total = db.execute(select(func.count()).select_from(VpnServer)).scalar_one()
        print(f"✓ {nuevos} servidor(es) agregado(s). Total activos: {total}")
        print("  Son direcciones de ejemplo para probar la recomendación; reemplácelas por las suyas.")
        if args.premium:
            from app.db.models import User
            u = db.execute(select(User).where(User.email == email_norm(args.premium))).scalar()
            if u is None:
                _fail(f"No existe la cuenta {args.premium}")
            # ENTERPRISE y no PREMIUM: los servidores marcados como premium requieren la
            # característica «premium_vpn», que solo trae ese plan (ver app/core/plans.py).
            u.plan = "ENTERPRISE"
            db.commit()
            print(f"✓ {u.email} pasó al plan ENTERPRISE: ya ve todos los servidores, incluidos los premium")
    finally:
        db.close()


def instalar_lectura(args: argparse.Namespace) -> None:
    """Instala en ESTE intérprete las librerías que leen y generan archivos.

    Se usa sys.executable a propósito: el error más común es instalar en un Python y ejecutar el
    servidor con otro, y entonces «pip install» parece haber funcionado pero el servidor sigue sin
    la librería.
    """
    print(f"Instalando en: {sys.executable}\n")
    r = subprocess.run([sys.executable, "-m", "pip", "install", *PAQUETES_LECTURA],
                       capture_output=True, text=True)
    if r.returncode:
        print((r.stdout or "")[-1500:])
        _fail(f"pip falló:\n{(r.stderr or '')[-800:]}")

    print("\nComprobando:")
    faltan = []
    for modulo, para in [("pypdf", "PDF"), ("docx", "Word"), ("openpyxl", "Excel"), ("pptx", "PowerPoint"),
                         ("PIL", "imágenes"), ("reportlab", "crear PDF"), ("matplotlib", "gráficos")]:
        try:
            __import__(modulo)
            print(f"  ✓ {para}")
        except ImportError:
            faltan.append(para)
            print(f"  ✗ {para}")

    try:
        import pytesseract
        idiomas = set(pytesseract.get_languages(config=""))
        print(f"  ✓ OCR de imágenes (idiomas: {', '.join(sorted(idiomas)) or 'ninguno'})")
        if "spa" not in idiomas:
            print("    → Sin el idioma español el OCR confunde las tildes. En Windows reinstale")
            print("      Tesseract marcando «Spanish»: https://github.com/UB-Mannheim/tesseract/wiki")
    except ImportError:
        print("  ✗ OCR de imágenes (falta el paquete pytesseract)")
    except Exception:  # noqa: BLE001 - el paquete está pero el programa Tesseract no
        print("  ✗ OCR: falta el programa Tesseract en el equipo")
        print("    → Windows: https://github.com/UB-Mannheim/tesseract/wiki (marque el idioma español)")
        print("    → Sin él, todo lo demás funciona: solo no se lee texto dentro de fotos.")

    if faltan:
        _fail("Quedaron pendientes: " + ", ".join(faltan))
    print("\n✓ Listo. Reinicie el servidor para que tome los cambios:  uvicorn app.main:app --reload")


def usar_ollama(args: argparse.Namespace) -> None:
    """Configura el asistente con un modelo local de Ollama y lo deja probado."""
    import httpx

    from app.core.config import PROJECT_ROOT, get_settings
    base = args.url.rstrip("/")
    raiz = base.removesuffix("/v1")

    print(f"Buscando Ollama en {raiz} ...")
    try:
        r = httpx.get(f"{raiz}/api/tags", timeout=5)
        r.raise_for_status()
        modelos = [m["name"] for m in r.json().get("models", [])]
    except Exception as e:  # noqa: BLE001
        _fail(f"No respondió: {type(e).__name__}.\n"
              "  1. Instale Ollama desde https://ollama.com/download y ábralo (queda en la bandeja del sistema)\n"
              "  2. En otra terminal:  ollama pull llama3.1:8b\n"
              "  3. Vuelva a ejecutar:  python -m app.cli usar-ollama")
    if not modelos:
        _fail("Ollama está corriendo pero no tiene modelos descargados.\n"
              "  Ejecute en otra terminal:  ollama pull llama3.1:8b   (unos 4,7 GB)\n"
              "  Equipos con poca memoria:  ollama pull llama3.2:3b   (unos 2 GB)\n"
              "  Luego repita: python -m app.cli usar-ollama")
    print("Modelos disponibles: " + ", ".join(modelos))
    modelo = args.modelo or next((m for m in modelos if "llama3.1" in m), modelos[0])
    if args.modelo and args.modelo not in modelos:
        _fail(f"El modelo '{args.modelo}' no está descargado. Ejecute:  ollama pull {args.modelo}")
    print(f"Usando: {modelo}")

    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        _fail("No existe el .env. Ejecute primero:  python -m app.cli setup")
    lineas = [ln for ln in env_path.read_text(encoding="utf-8").splitlines()
              if not ln.startswith(("GUARDIAN_LLM_PROVIDER=", "GUARDIAN_LLM_BASE_URL=", "GUARDIAN_LLM_MODEL=",
                                    "GUARDIAN_WEB_BROWSING_ENABLED="))]
    lineas += ["GUARDIAN_LLM_PROVIDER=openai", f"GUARDIAN_LLM_BASE_URL={base}",
               f"GUARDIAN_LLM_MODEL={modelo}", "GUARDIAN_WEB_BROWSING_ENABLED=true"]
    env_path.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print(f"✓ {env_path} actualizado")

    get_settings.cache_clear()
    args.pregunta = args.pregunta or "En una frase: ¿qué es el phishing?"
    probar_ia(args)
    print("\nReinicie el servidor para que el cambio tome efecto:  uvicorn app.main:app --reload")


def renombrar_asistente(args: argparse.Namespace) -> None:
    """Cambia el nombre del asistente en las cuentas que aún tienen el anterior.

    No toca a quien ya lo personalizó: ese nombre lo eligió la persona.
    """
    from app.db.models import PersonalityProfile
    init_db()
    db = SessionLocal()
    try:
        filas = db.execute(select(PersonalityProfile)
                           .where(PersonalityProfile.assistant_name == args.anterior)).scalars().all()
        for fila in filas:
            fila.assistant_name = args.nuevo
        db.commit()
        print(f"✓ {len(filas)} cuenta(s) actualizada(s): «{args.anterior}» → «{args.nuevo}»")
    finally:
        db.close()


def probar_ia(args: argparse.Namespace) -> None:
    """Comprueba de extremo a extremo que el asistente usa el modelo avanzado y puede navegar."""
    import httpx

    from app.ai import assistant
    from app.core.config import get_settings
    s = get_settings()

    if s.llm_kind == "ninguno":
        _fail("El asistente no tiene un modelo avanzado configurado.\n\n"
              "  Opción A — Anthropic (en la nube, de pago por uso):\n"
              "    1. Cree una clave en https://console.anthropic.com  (Settings -> API keys)\n"
              "    2. En el .env:  GUARDIAN_ANTHROPIC_API_KEY=sk-ant-...\n\n"
              "  Opción B — modelo local con Ollama (gratis, sin clave, sus datos no salen del equipo):\n"
              "    1. Instale https://ollama.com y ejecute:  ollama pull llama3.1:8b\n"
              "    2. En el .env:\n"
              "         GUARDIAN_LLM_PROVIDER=openai\n"
              "         GUARDIAN_LLM_BASE_URL=http://localhost:11434/v1\n"
              "         GUARDIAN_LLM_MODEL=llama3.1:8b\n\n"
              "  Luego reinicie el servidor y ejecute: python -m app.cli probar-ia")
    print(f"Proveedor: {s.llm_kind}")
    print(f"Modelo:    {s.anthropic_model if s.llm_kind == 'anthropic' else s.llm_model or 'gpt-4o-mini'}")
    print(f"Navegación web:     {'activada' if s.web_browsing_enabled else 'desactivada'}")

    persona = assistant.Persona(name="Asistente AI")
    pregunta = args.pregunta or "En una frase: ¿qué es el phishing?"
    print(f"\nPreguntando: {pregunta}")
    try:
        reply = assistant.respond(pregunta, [], persona)
    except Exception as e:  # noqa: BLE001
        _fail(f"Falló la consulta: {type(e).__name__}: {e}")
    print(f"\nProveedor: {reply.provider}")
    print(f"Respuesta: {reply.text[:400]}")
    if reply.sources:
        print("Fuentes: " + ", ".join(so["url"] for so in reply.sources[:3]))
    if reply.provider in ("anthropic", "openai"):
        print("\n✓ Conectado al modelo avanzado.")
        return
    if reply.provider == "local_fallback":
        print("\n✗ Hay clave, pero la llamada falló. Causas frecuentes:")
        print("  - Clave inválida o revocada, o sin saldo en la cuenta")
        print("  - Sin salida a internet (proxy, firewall o VPN corporativa)")
        print(f"  - Nombre de modelo incorrecto: '{s.anthropic_model}'. Ajuste GUARDIAN_ANTHROPIC_MODEL")
        try:
            if s.llm_kind == "anthropic":
                r = httpx.post("https://api.anthropic.com/v1/messages",
                               headers={"x-api-key": s.anthropic_api_key, "anthropic-version": "2023-06-01",
                                        "content-type": "application/json"},
                               json={"model": s.anthropic_model, "max_tokens": 16,
                                     "messages": [{"role": "user", "content": "ping"}]}, timeout=20)
            else:
                cabeceras = {"content-type": "application/json"}
                if s.llm_api_key:
                    cabeceras["Authorization"] = f"Bearer {s.llm_api_key}"
                r = httpx.post(f"{s.llm_base_url.rstrip('/')}/chat/completions", headers=cabeceras,
                               json={"model": s.llm_model or "gpt-4o-mini", "max_tokens": 16,
                                     "messages": [{"role": "user", "content": "ping"}]}, timeout=20)
            print(f"\nRespuesta directa del proveedor: HTTP {r.status_code} {r.text[:300]}")
        except Exception as e:  # noqa: BLE001
            print(f"\nNo hubo conexión con api.anthropic.com: {type(e).__name__}: {e}")
        sys.exit(1)
    _fail("El asistente respondió en modo local: revise el .env y reinicie el servidor")


def verify_audit(_: argparse.Namespace) -> None:
    init_db()
    db = SessionLocal()
    try:
        r = audit.verify_chain(db)
    finally:
        db.close()
    if r["integra"]:
        print(f"✓ Bitácora íntegra ({r['registros_verificados']} registros)")
    else:
        _fail(f"Bitácora alterada a partir del registro {r['primer_registro_alterado']}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Operación de GuardianIA")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("setup", help="crea el .env con claves nuevas")
    p.add_argument("--force", action="store_true", help="reemplaza un .env existente")
    p.set_defaults(fn=setup)
    p = sub.add_parser("doctor", help="revisa la instalación")
    p.add_argument("--registro", action="store_true", help="además prueba un registro real")
    p.set_defaults(fn=doctor)
    sub.add_parser("generate-keys").set_defaults(fn=generate_keys)
    p = sub.add_parser("migrar-a-nube", help="copia las cuentas y datos del PC a una base PostgreSQL en la nube")
    p.add_argument("url", help="cadena de conexión de Neon/Supabase (postgresql://usuario:clave@host/base)")
    p.set_defaults(fn=migrar_a_nube)
    p = sub.add_parser("create-admin")
    p.add_argument("email")
    p.add_argument("name")
    p.add_argument("role", nargs="?", default="admin")
    p.set_defaults(fn=create_admin)
    p = sub.add_parser("enroll-mfa")
    p.add_argument("email")
    p.add_argument("--reset", action="store_true")
    p.set_defaults(fn=enroll_mfa)
    p = sub.add_parser("entrenar", help="entrena las redes neuronales con los datos de este servidor")
    p.add_argument("modelo", choices=["antivirus", "vitales", "intencion"])
    p.add_argument("--epocas", type=int, default=400)
    p.set_defaults(fn=entrenar)
    p = sub.add_parser("vpn-servidor", help="registra un servidor WireGuard real")
    p.add_argument("--id", required=True, help="identificador corto, p. ej. co-bog-real")
    p.add_argument("--ciudad", required=True)
    p.add_argument("--pais", required=True, help="código de dos letras: CO, US, ES…")
    p.add_argument("--endpoint", required=True, help="host:puerto público, p. ej. 45.33.10.2:51820")
    p.add_argument("--clave-publica", required=True, dest="clave_publica", help="clave pública del servidor")
    p.add_argument("--ip-salida", dest="ip_salida", help="IP pública por la que sale el tráfico (por defecto, la del endpoint)")
    p.add_argument("--subred", default="10.66.0.0/24")
    p.add_argument("--dns", default="1.1.1.1, 9.9.9.9")
    p.add_argument("--premium", action="store_true")
    p.set_defaults(fn=vpn_servidor)
    p = sub.add_parser("sembrar-vpn", help="carga servidores VPN de ejemplo")
    p.add_argument("--premium", metavar="CORREO", help="además, pasa esa cuenta al plan ENTERPRISE para probarlo todo")
    p.set_defaults(fn=sembrar_vpn)
    sub.add_parser("instalar-lectura", help="instala los lectores de PDF, Word, Excel e imágenes").set_defaults(
        fn=instalar_lectura)
    p = sub.add_parser("usar-ollama", help="conecta un modelo local de Ollama")
    p.add_argument("modelo", nargs="?", help="nombre del modelo ya descargado (por defecto, el primero)")
    p.add_argument("--url", default="http://localhost:11434/v1", help="URL de Ollama")
    p.add_argument("--pregunta", default=None)
    p.set_defaults(fn=usar_ollama)
    p = sub.add_parser("renombrar-asistente", help="cambia el nombre del asistente en las cuentas existentes")
    p.add_argument("nuevo", nargs="?", default="Asistente AI")
    p.add_argument("--anterior", default="Guardian")
    p.set_defaults(fn=renombrar_asistente)
    p = sub.add_parser("probar-ia", help="comprueba la conexión con el modelo avanzado")
    p.add_argument("pregunta", nargs="?", help="pregunta de prueba")
    p.set_defaults(fn=probar_ia)
    sub.add_parser("verify-audit").set_defaults(fn=verify_audit)
    args = parser.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
