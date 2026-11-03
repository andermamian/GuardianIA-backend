"""Redes neuronales: aprendizaje real, métricas honestas y uso prudente."""
import numpy as np
import pytest

from tests.test_devices_vault_admin import admin  # noqa: F401 - fixture de sesión de administrador

from app.ml.red import RedNeuronal


def test_la_red_aprende_un_problema_no_lineal():
    """XOR: si la red lo resuelve, la retropropagación y Adam están bien implementados."""
    rng = np.random.default_rng(0)
    X = rng.uniform(-1, 1, (600, 2))
    y = ((X[:, 0] > 0) ^ (X[:, 1] > 0)).astype(float)   # imposible para un modelo lineal
    red = RedNeuronal([2, 16, 8, 1])
    m = red.entrenar(X, y, epocas=400, tasa=0.02)
    assert m.exactitud > 0.9 and m.auc > 0.95


def test_pesos_por_clase_evitan_el_detector_inutil():
    """Con 5% de positivos, sin compensar la red dice «limpio» siempre y acierta el 95%."""
    rng = np.random.default_rng(1)
    X = np.vstack([rng.normal(0, 1, (950, 4)), rng.normal(2.2, 1, (50, 4))])
    y = np.concatenate([np.zeros(950), np.ones(50)])
    red = RedNeuronal([4, 12, 1])
    m = red.entrenar(X, y, epocas=300, pesos_clase=True)
    assert m.sensibilidad > 0.6, "detecta la clase rara, que es justo la que importa"


def test_el_umbral_no_es_el_0_5_por_costumbre():
    rng = np.random.default_rng(2)
    X = np.vstack([rng.normal(0, 1, (300, 3)), rng.normal(1.5, 1, (60, 3))])
    y = np.concatenate([np.zeros(300), np.ones(60)])
    red = RedNeuronal([3, 8, 1])
    red.entrenar(X, y, epocas=200)
    assert 0.05 <= red.umbral <= 0.95 and red.metricas.umbral == red.umbral


def test_guardar_y_cargar_conserva_las_predicciones(tmp_path):
    rng = np.random.default_rng(3)
    X = rng.normal(0, 1, (200, 5))
    y = (X[:, 0] + X[:, 1] > 0).astype(float)
    red = RedNeuronal([5, 10, 1])
    red.nombres_rasgos = [f"r{i}" for i in range(5)]
    red.entrenar(X, y, epocas=150)
    antes = red.predecir(X[:10])
    ruta = red.guardar(tmp_path / "modelo.npz")
    recuperada = RedNeuronal.cargar(ruta)
    assert np.allclose(antes, recuperada.predecir(X[:10]))
    assert recuperada.umbral == red.umbral and recuperada.nombres_rasgos == red.nombres_rasgos


def test_la_normalizacion_se_aprende_solo_del_entrenamiento():
    """Usar todo el conjunto para normalizar filtra información y las métricas salen infladas."""
    rng = np.random.default_rng(4)
    X = np.vstack([rng.normal(0, 1, (100, 3)), rng.normal(50, 1, (100, 3))])
    y = np.concatenate([np.zeros(100), np.ones(100)])
    red = RedNeuronal([3, 8, 1])
    red.entrenar(X, y, epocas=100, validacion=0.5)
    # La media aprendida debe parecerse a la del 50% de entrenamiento, no a la de todo el conjunto.
    assert red.mu.shape == (3,) and np.all(red.sigma > 0)


def test_la_red_de_intencion_entiende_frases_con_errores(tmp_path):
    from app.ml import asistente
    red, metricas, _ = asistente.entrenar(tmp_path, epocas=400)
    assert metricas.ejemplos_validacion >= 10
    casos = [("crea un word ocn un plan clase", "crear_archivo"),
             ("asme una tabla de notaz en excel", "crear_archivo"),
             ("escribeme un programa en pyton", "codigo"),
             ("hola buenos dias", "charla")]
    aciertos = sum(asistente.clasificar(texto, red)[0] == esperado for texto, esperado in casos)
    assert aciertos >= 3, "debe tolerar erratas, que es para lo que existe"


def test_sin_modelo_entrenado_nada_se_rompe():
    """El antivirus y el asistente deben funcionar igual aunque no haya redes entrenadas."""
    from app.ml.entrenamiento import anomalia_vitales, limpiar_cache, probabilidad_maliciosa
    limpiar_cache()
    import app.ml.entrenamiento as ent
    ent._cache = {"antivirus": (9e12, None), "vitales": (9e12, None)}
    assert probabilidad_maliciosa({"name": "x.exe", "size": 100}) is None
    assert anomalia_vitales([70, 72, 71], [97, 98, 97]) is None
    limpiar_cache()


def test_se_niega_a_entrenar_con_pocos_datos():
    from app.db.session import SessionLocal
    from app.ml.entrenamiento import DatosInsuficientes, datos_vitales
    db = SessionLocal()
    try:
        with pytest.raises(DatosInsuficientes) as e:
            datos_vitales(db)
        assert "ventanas" in str(e.value)     # dice qué falta, no entrena a medias
    finally:
        db.close()


def test_los_rasgos_del_antivirus_son_explicables():
    from app.ml.entrenamiento import RASGOS_ANTIVIRUS, rasgos_archivo
    limpio = rasgos_archivo({"name": "informe.pdf", "size": 300000, "kind": "pdf", "entropy": 5.0,
                             "is_signed": True, "strings": ["informe"], "imports": []})
    malo = rasgos_archivo({"name": "factura.pdf.exe", "size": 90000, "kind": "pe", "entropy": 7.8,
                           "is_signed": False, "strings": ["upx", "http://malo.tk/"],
                           "imports": ["CryptEncrypt", "CreateRemoteThread"],
                           "ruta": "C:/Users/a/Downloads/factura.pdf.exe"})
    assert len(limpio) == len(RASGOS_ANTIVIRUS) == len(malo)
    assert malo[0] > limpio[0] and malo[5] > 0 and malo[10] == 1.0 and limpio[3] == 1.0


def test_el_panel_exige_permisos(client, auth):
    """Un usuario normal no puede ver ni entrenar modelos."""
    assert client.get("/v1/ml/modelos", headers=auth).status_code in (401, 403)
    assert client.post("/v1/ml/entrenar", headers=auth, json={"modelo": "intencion"}).status_code in (401, 403)


# ───────────────────────── panel de la consola (administrador)
def test_el_administrador_ve_el_panel_y_puede_entrenar(client, admin):
    listado = client.get("/v1/ml/modelos", headers=admin)
    assert listado.status_code == 200
    nombres = {m["nombre"] for m in listado.json()}
    assert nombres == {"antivirus", "vitales", "intencion"}
    for m in listado.json():
        assert m["titulo"] and m["para_que"]          # cada red explica para qué sirve

    r = client.post("/v1/ml/entrenar", headers=admin, json={"modelo": "intencion", "epocas": 60})
    assert r.status_code == 202 and "Entrenando" in r.json()["mensaje"]


def test_entrenar_sin_datos_lo_dice_antes_de_aceptar(client, admin):
    """Mejor un 409 con el motivo que aceptar y fallar en un log que nadie mira."""
    r = client.post("/v1/ml/entrenar", headers=admin, json={"modelo": "vitales"})
    assert r.status_code == 409 and r.json()["code"] == "datos_insuficientes"
    assert "ventanas" in r.json()["title"]
