# Servidor VPN propio de GuardianIA (gratis en Google Cloud)

VPN independiente: no depende de Proton, Tor ni Cloudflare. Protocolo WireGuard (estándar abierto y
auditado). El servidor es suyo: sin registros, DNS propio y freno de consumo para que nunca le cobren.

## ⚠️ Lo más importante: red «Standard»
Google Cloud regala 1 e2-micro al mes en us-west1, us-central1 o us-east1. Pero con la red por defecto
(«Premium») solo da **1 GB** gratis de salida al mes; con la red **Standard** da **200 GB por región**.
Con una VPN, 1 GB se va en un video. Los comandos de abajo crean la máquina en red Standard.
Además, el agente frena el reenvío al llegar a 190 GB del mes.

## 1. Crear la máquina (Google Cloud Shell, el ícono «>_» arriba a la derecha de la consola)
```bash
gcloud compute instances create guardian-vpn \
  --zone=us-east1-b --machine-type=e2-micro \
  --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=30GB --boot-disk-type=pd-standard \
  --network-tier=STANDARD --tags=guardian-vpn
gcloud compute firewall-rules create guardian-vpn-wg  --allow=udp:51820 --target-tags=guardian-vpn
gcloud compute firewall-rules create guardian-vpn-api --allow=tcp:8844  --target-tags=guardian-vpn
```
us-east1 (Carolina del Sur) es la región gratuita más cercana a Colombia.

## 2. Instalar el servidor
Suba `agente.py` e `instalar.sh` a Cloud Shell (menú ⋮ → «Subir») y ejecute:
```bash
gcloud compute scp --zone=us-east1-b agente.py instalar.sh guardian-vpn:~
gcloud compute ssh guardian-vpn --zone=us-east1-b --command "sudo bash instalar.sh"
```
Al final muestra tres datos: **dirección de la API**, **huella del certificado** y **ficha secreta**
(solo se muestra una vez: guárdela).

## 3. Alerta de presupuesto (recomendado)
Consola → Facturación → Presupuestos y alertas → crear presupuesto de **USD 1** con aviso al 50 %.

## Qué protege y qué no
- ✅ Su operador y el WiFi público no ven su tráfico ni los sitios que visita (DNS propio, sin fugas).
- ✅ Los sitios le ven con una IP de EE. UU.
- ⚠️ Google sabe que el servidor es suyo: es privacidad, no anonimato total. Para anonimato, combínelo
  con Tor (modo «VPN + Tor»).
