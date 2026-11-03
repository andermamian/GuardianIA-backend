"""Panel de redes neuronales: qué modelos hay, qué tan buenos son y cuándo reentrenar.

Solo para administradores. Entrenar consume CPU y cambia cómo se comporta la detección, así que es
una acción registrada en la bitácora, no un botón inocente.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Request
from pydantic import BaseModel, Field

from app.api.deps import DB, CurrentUser, Principal, client_ip, require
from app.core import audit
from app.core.errors import ApiError
from app.db.session import SessionLocal
from app.ml import asistente as ml_asistente
from app.ml.entrenamiento import (DatosInsuficientes, activar, carpeta_modelos, entrenar_antivirus,
                                  entrenar_vitales, limpiar_cache, versiones)
from app.schemas.common import Msg

router = APIRouter(prefix="/ml", tags=["Redes neuronales"])

DESCRIPCION = {
    "antivirus": ("Detección de malware", "Aprende combinaciones de rasgos que ninguna regla "
                  "describe. Entra como una señal más del motor, nunca como veredicto único."),
    "vitales": ("Anomalías en signos vitales", "Autoencoder: aprende la normalidad de cada persona "
                "y marca lo que no logra reconstruir. No diagnostica."),
    "intencion": ("Intención del asistente", "Entiende qué le piden aunque escriban con errores. "
                  "Complementa las reglas; nunca cancela una detección de ellas."),
}


@router.get("/modelos")
def modelos(p: Principal = require("ai:read")):
    """Estado de las tres redes: versión activa, métricas, curva de aprendizaje e historial."""
    salida = []
    for nombre, (titulo, para_que) in DESCRIPCION.items():
        lista = versiones(nombre)
        activa = next((v for v in lista if v["activa"]), None)
        salida.append({
            "nombre": nombre, "titulo": titulo, "para_que": para_que,
            "entrenado": activa is not None, "activa": activa,
            "historial_versiones": [{"version": v["version"], "creado": v["creado"], "activa": v["activa"],
                                     "f1": v["metricas"].get("f1"), "exactitud": v["metricas"].get("exactitud"),
                                     "ejemplos": v["metricas"].get("ejemplos_entrenamiento")}
                                    for v in lista[:10]],
            "trabajo": TRABAJOS.get(nombre),
        })
    return salida


class ActivarIn(BaseModel):
    version: str = Field(max_length=20)


@router.post("/modelos/{nombre}/activar", response_model=Msg)
def activar_version(nombre: str, body: ActivarIn, request: Request, db: DB,
                    p: Principal = require("ai:train")):
    """Vuelve a una versión anterior. Si un modelo nuevo detecta peor, se deshace en un clic."""
    if nombre not in DESCRIPCION:
        raise ApiError(404, "modelo_desconocido", "Ese modelo no existe")
    if not activar(nombre, body.version):
        raise ApiError(404, "version_no_encontrada", "Esa versión no está en el servidor")
    audit.record(db, "ml.activar_version", actor_id=p.user.id, ip=client_ip(request), level="warning",
                 detail={"modelo": nombre, "version": body.version})
    return Msg(mensaje=f"«{nombre}» quedó en la versión {body.version}")


@router.get("/trabajos/{nombre}")
def trabajo(nombre: str, p: Principal = require("ai:read")):
    """Progreso del entrenamiento en curso: la interfaz lo consulta para mostrar la barra."""
    return TRABAJOS.get(nombre) or {"estado": "inactivo"}


class EntrenarIn(BaseModel):
    modelo: str = Field(pattern="^(antivirus|vitales|intencion)$")
    epocas: int = Field(400, ge=50, le=2000)


@router.post("/entrenar", response_model=Msg, status_code=202)
def entrenar(body: EntrenarIn, tareas: BackgroundTasks, request: Request, db: DB,
             p: Principal = require("ai:train")):
    """Lanza el entrenamiento en segundo plano: bloquear la petición sería mala idea."""
    # Se comprueba antes de aceptar: es mejor decir «faltan datos» ahora que en un log que nadie mira.
    if body.modelo != "intencion":
        try:
            from app.ml.entrenamiento import datos_antivirus, datos_vitales
            datos_antivirus(db) if body.modelo == "antivirus" else datos_vitales(db)
        except DatosInsuficientes as e:
            raise ApiError(409, "datos_insuficientes", str(e)) from e

    audit.record(db, "ml.entrenar", actor_id=p.user.id, ip=client_ip(request), level="warning",
                 detail={"modelo": body.modelo, "epocas": body.epocas})
    tareas.add_task(_entrenar_en_segundo_plano, body.modelo, body.epocas)
    return Msg(mensaje=f"Entrenando «{body.modelo}». Tarda de segundos a unos minutos; "
                       "recargue esta pantalla para ver las métricas.")


# Progreso de los entrenamientos en curso. Vive en memoria a propósito: si el servidor se reinicia,
# el entrenamiento se perdió de todos modos y dejar un estado «en curso» en la base engañaría.
TRABAJOS: dict[str, dict] = {}


def _entrenar_en_segundo_plano(modelo: str, epocas: int) -> None:
    import time
    inicio = time.time()
    TRABAJOS[modelo] = {"estado": "entrenando", "epoca": 0, "epocas": epocas, "perdida": None,
                        "curva": [], "iniciado": datetime.now(UTC).isoformat()}

    def avance(epoca: int, perdida: float) -> None:
        trabajo = TRABAJOS.get(modelo)
        if trabajo is not None:
            trabajo["epoca"] = epoca
            trabajo["perdida"] = round(perdida, 5)
            trabajo["curva"] = (trabajo["curva"] + [{"epoca": epoca, "perdida": round(perdida, 5)}])[-60:]

    db = SessionLocal()
    try:
        if modelo == "intencion":
            _red, metricas, _ruta = ml_asistente.entrenar(carpeta_modelos(), epocas=epocas)
        elif modelo == "antivirus":
            metricas = entrenar_antivirus(db, epocas=epocas, registro=avance).metricas
        else:
            metricas = entrenar_vitales(db, epocas=epocas, registro=avance).metricas
        limpiar_cache()
        TRABAJOS[modelo] = {**TRABAJOS.get(modelo, {}), "estado": "listo",
                            "segundos": round(time.time() - inicio, 1),
                            "metricas": metricas.to_dict()}
    except Exception as e:  # noqa: BLE001 - un fallo aquí no puede tumbar el servidor
        import logging
        logging.getLogger("guardian").exception("falló el entrenamiento de %s", modelo)
        TRABAJOS[modelo] = {"estado": "error", "mensaje": f"{type(e).__name__}: {e}"[:200]}
    finally:
        db.close()


class PruebaIn(BaseModel):
    texto: str = Field(min_length=2, max_length=500)


@router.post("/probar-intencion")
def probar_intencion(body: PruebaIn, p: Principal = require("ai:read")):
    """Escribir una frase y ver qué entiende la red: la mejor forma de confiar (o no) en ella."""
    from app.ml.entrenamiento import modelo_activo
    red = modelo_activo("intencion")
    if red is None:
        raise ApiError(409, "sin_modelo", "Todavía no hay una red de intención entrenada")
    import numpy as np
    probabilidades = red.predecir(np.array([ml_asistente.vectorizar(body.texto)]))[0]
    pares = sorted(zip(ml_asistente.INTENCIONES, probabilidades.tolist()), key=lambda x: -x[1])
    return {"intencion": pares[0][0], "confianza": round(pares[0][1], 3),
            "todas": [{"intencion": n, "probabilidad": round(v, 3)} for n, v in pares]}


@router.get("/intencion/movil")
def intencion_para_movil(p: CurrentUser):
    """Pesos de la red de intención para ejecutarla DENTRO del teléfono (app Android).

    Así la app entiende la intención sin conexión y sin mandar el texto a ningún lado. Los pesos no
    son secretos (cualquiera con el código puede entrenarlos igual), pero se piden con sesión para
    no exponer la API a scrapers. La app compara `version` y solo descarga si cambió.
    """
    from app.ml.entrenamiento import activa_de, modelo_activo
    red = modelo_activo("intencion")
    version = activa_de("intencion")
    if red is None or not version:
        raise ApiError(409, "sin_modelo", "Todavía no hay una red de intención entrenada")
    return {
        "formato": "guardian-mlp-1", "version": version, "intenciones": ml_asistente.INTENCIONES,
        "dimensiones": ml_asistente.DIMENSIONES, "ngramas": list(ml_asistente.NGRAMAS),
        "hash": "fnv1a32", "salida": red.salida, "capas": red.capas,
        "mu": red.mu.tolist(), "sigma": red.sigma.tolist(),
        "W": [w.tolist() for w in red.W], "b": [b.tolist() for b in red.b],
    }
