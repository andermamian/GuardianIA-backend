# GuardianIA en la nube (Render, Railway, Fly…): el mismo servidor del PC, con HTTPS que pone el hosting.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# OCR de imágenes y fotogramas de video: opcionales, pero el asistente los usa para leer adjuntos.
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-spa ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
COPY web ./web
COPY skills ./skills
COPY docs ./docs

# El hosting define $PORT. --proxy-headers: la IP real del cliente (límite de intentos y auditoría).
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
