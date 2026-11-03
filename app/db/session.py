from __future__ import annotations

import importlib
from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine(url: str):
    kwargs: dict = {"pool_pre_ping": True, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            from sqlalchemy.pool import StaticPool
            kwargs["poolclass"] = StaticPool
    eng = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _pragmas(conn, _):  # integridad referencial y concurrencia en SQLite
            cur = conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()
    return eng


engine = _make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    importlib.import_module("app.db.models")  # registra las tablas en Base.metadata
    Base.metadata.create_all(engine)         # crea las tablas que falten
    _agregar_columnas_faltantes()            # y las columnas nuevas en tablas que ya existían


def _literal_por_defecto(columna) -> str | None:
    """Traduce el valor por defecto del modelo a un literal SQL, si es un valor simple."""
    defecto = getattr(columna.default, "arg", None) if columna.default is not None else None
    if defecto is None or callable(defecto):
        return None
    if isinstance(defecto, bool):
        return "1" if defecto else "0"
    if isinstance(defecto, (int, float)):
        return str(defecto)
    if isinstance(defecto, str):
        escapado = defecto.replace("'", "''")
        return f"'{escapado}'"
    return None


def _agregar_columnas_faltantes() -> None:
    """Agrega columnas nuevas a tablas ya creadas.

    `create_all` crea tablas que faltan, pero NO altera las existentes: por eso una base creada con
    una versión anterior falla con «no such column». Esta migración mínima compara el modelo con la
    tabla real y agrega lo que falte. Solo agrega: nunca borra ni cambia tipos, que es donde una
    migración automática se vuelve peligrosa. Para cambios de ese calibre, Alembic.
    """
    from sqlalchemy import inspect, text
    from sqlalchemy.schema import CreateColumn

    inspector = inspect(engine)
    tablas = set(inspector.get_table_names())
    agregadas = []
    with engine.begin() as conexion:
        for tabla in Base.metadata.sorted_tables:
            if tabla.name not in tablas:
                continue
            existentes = {c["name"] for c in inspector.get_columns(tabla.name)}
            for columna in tabla.columns:
                if columna.name in existentes:
                    continue
                definicion = str(CreateColumn(columna).compile(engine))
                # SQLite no admite ADD COLUMN NOT NULL sin DEFAULT. Los valores por defecto del
                # modelo viven en Python, no en el SQL, así que aquí se traducen; y si no hay
                # ninguno, se quita el NOT NULL para no romper la tabla existente.
                if " NOT NULL" in definicion and "DEFAULT" not in definicion:
                    literal = _literal_por_defecto(columna)
                    definicion = (f"{definicion} DEFAULT {literal}" if literal is not None
                                  else definicion.replace(" NOT NULL", ""))
                conexion.execute(text(f"ALTER TABLE {tabla.name} ADD COLUMN {definicion}"))
                agregadas.append(f"{tabla.name}.{columna.name}")
    if agregadas:
        import logging
        logging.getLogger("guardian").info(
            "Base de datos actualizada: %s columna(s) agregada(s) (%s)",
            len(agregadas), ", ".join(agregadas[:8]) + ("…" if len(agregadas) > 8 else ""))
