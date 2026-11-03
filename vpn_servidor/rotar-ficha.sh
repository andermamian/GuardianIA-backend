#!/usr/bin/env bash
# Cambia la ficha secreta del servidor GuardianIA VPN sin tocar claves, certificado ni dispositivos.
# La ficha anterior deja de servir al instante (el agente lee config.json en cada petición).
# Uso (en la máquina):  sudo bash rotar-ficha.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Ejecute con sudo."; exit 1; }
DIR=/etc/guardian-vpn
[[ -f $DIR/config.json && -f $DIR/api.crt ]] || { echo "ERROR: el servidor no está instalado (falta $DIR)."; exit 1; }
umask 077
FICHA=$(openssl rand -base64 33 | tr -d '/+=' | cut -c1-40)
FICHA_SHA=$(printf '%s' "$FICHA" | sha256sum | cut -d' ' -f1)
python3 - "$FICHA_SHA" "$DIR/config.json" <<'PY'
import json, os, sys
sha, ruta = sys.argv[1], sys.argv[2]
c = json.load(open(ruta, encoding="utf-8"))
c["ficha_sha256"] = sha
tmp = ruta + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(c, f)
os.chmod(tmp, 0o600)
os.replace(tmp, ruta)
PY
URL=$(python3 -c "import json;c=json.load(open('$DIR/config.json'));print('https://%s:%s' % (c['endpoint'].rsplit(':',1)[0], c.get('puerto_api',8844)))")
HUELLA=$(openssl x509 -in "$DIR/api.crt" -noout -fingerprint -sha256 | cut -d= -f2)
echo "GIA_URL=$URL"
echo "GIA_HUELLA=$HUELLA"
echo "GIA_FICHA=$FICHA"
