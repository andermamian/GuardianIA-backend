"""v4.5: el asistente recibe y lee fotos, videos grandes, ZIP/TAR, audio y cualquier otro archivo."""
import io
import shutil
import subprocess
import tarfile
import zipfile

import pytest

from app.ai import archivos, lectura


def _zip(tmp_path, miembros, nombre="p.zip"):
    ruta = tmp_path / nombre
    with zipfile.ZipFile(ruta, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in miembros.items():
            z.writestr(n, d)
    return ruta


def _png():
    from PIL import Image
    b = io.BytesIO()
    Image.new("RGB", (40, 30), (200, 30, 30)).save(b, "PNG")
    return b.getvalue()


def test_zip_lee_codigo_resumen_y_omite_secretos(tmp_path):
    ruta = _zip(tmp_path, {"README.md": "# Mi app\nHace cosas", "src/main.py": "print('hola mundo')\n",
                           ".env": "CLAVE=secreta123", "node_modules/x/i.js": "var x=1", "foto.png": _png(),
                           "datos.bin": bytes(range(256)) * 4})
    r = archivos.leer(ruta, "p.zip")
    t = r.documento.texto
    assert t.startswith("[RESUMEN]") and "ZIP" in t and "posibles credenciales" in t
    assert "[src/main.py]" in t and "hola mundo" in t and "Mi app" in t
    assert "secreta123" not in t and "var x=1" not in t
    assert len(r.imagenes) == 1


def test_zip_danado_y_zip_anidado(tmp_path):
    mal = tmp_path / "m.zip"
    mal.write_bytes(b"PK\x03\x04" + b"basura" * 10)
    with pytest.raises(lectura.NoSePuedeLeer):
        archivos.leer(mal, "m.zip")
    interior = io.BytesIO()
    with zipfile.ZipFile(interior, "w") as z:
        z.writestr("a.txt", "texto escondido adentro")
    ruta = _zip(tmp_path, {"inner.zip": interior.getvalue()}, "o.zip")
    assert "texto escondido adentro" in archivos.leer(ruta, "o.zip").documento.texto


def test_tar_gz_y_gzip(tmp_path):
    ruta = tmp_path / "x.tar.gz"
    with tarfile.open(ruta, "w:gz") as t:
        datos = b"def f():\n    return 42\n"
        info = tarfile.TarInfo("pkg/mod.py")
        info.size = len(datos)
        t.addfile(info, io.BytesIO(datos))
    r = archivos.leer(ruta, "x.tar.gz")
    assert "[pkg/mod.py]" in r.documento.texto and "return 42" in r.documento.texto
    import gzip
    g = tmp_path / "log.txt.gz"
    g.write_bytes(gzip.compress(b"linea de log importante\n"))
    assert "linea de log importante" in archivos.leer(g, "log.txt.gz").documento.texto


def test_imagen_sin_texto_no_falla_y_da_miniatura(tmp_path):
    f = tmp_path / "foto.png"
    f.write_bytes(_png())
    r = archivos.leer(f, "foto.png")
    assert r.clase == "imagen" and len(r.imagenes) == 1 and "40x30" in r.documento.texto


def test_binario_desconocido_se_admite_con_honestidad(tmp_path):
    f = tmp_path / "raro.xyz"
    f.write_bytes(b"\x00\x01\x02\xff" * 100)
    r = archivos.leer(f, "raro.xyz")
    assert r.clase == "binario" and "no sé leer" in r.documento.texto


def test_7z_pide_convertir(tmp_path):
    f = tmp_path / "a.7z"
    f.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"0" * 50)
    with pytest.raises(lectura.NoSePuedeLeer, match="ZIP"):
        archivos.leer(f, "a.7z")


def test_texto_sin_extension_conocida(tmp_path):
    f = tmp_path / "notas.lista"
    f.write_text("comprar leche\nllamar a Ana\n")
    assert "llamar a Ana" in archivos.leer(f, "notas.lista").documento.texto


@pytest.mark.skipif(not (shutil.which("ffmpeg") and shutil.which("ffprobe")), reason="sin ffmpeg")
def test_video_da_metadatos_y_fotogramas(tmp_path):
    v = tmp_path / "v.mp4"
    subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc=duration=6:size=320x240:rate=10",
                    "-pix_fmt", "yuv420p", str(v)], check=True)
    r = archivos.leer(v, "v.mp4")
    assert r.clase == "video" and len(r.imagenes) >= 3
    assert "320x240" in r.documento.texto and "fotogramas" in r.documento.texto


# ─────────────────────────────────────────────── por la API
def test_api_sube_zip_y_el_resumen_acompana_la_pregunta(client, auth, tmp_path):
    ruta = _zip(tmp_path, {"main.py": "def saludar():\n    return 'hola'\n", "README.md": "Proyecto de prueba"})
    with open(ruta, "rb") as f:
        r = client.post("/v1/assistant/attachments", headers=auth, files={"file": ("p.zip", f, "application/zip")})
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["clase"] == "zip" and "ZIP" in j["vista_previa"]
    docs_texto = lectura.Documento("p.zip", "", "[RESUMEN] x\n\ncosa", 0, False, "")
    docs_texto.fragmentos = lectura.fragmentar(docs_texto.texto)
    ctx, _ = lectura.contexto_para("¿qué hay de otra cosa totalmente distinta?", [docs_texto])
    assert "[RESUMEN]" in ctx


def test_api_foto_guarda_miniatura_como_lista(client, auth):
    r = client.post("/v1/assistant/attachments", headers=auth, files={"file": ("f.png", _png(), "image/png")})
    assert r.status_code == 201 and r.json()["imagenes"] == 1


def test_api_corta_archivos_sobre_el_limite(client, auth, monkeypatch):
    import app.api.v1.assistant as api_a
    from app.core.config import Settings
    monkeypatch.setattr(api_a, "get_settings", lambda: Settings(env="test", adjunto_max_mb=1))
    r = client.post("/v1/assistant/attachments", headers=auth,
                    files={"file": ("g.txt", b"a" * (2 * 1024 * 1024), "text/plain")})
    assert r.status_code == 413
