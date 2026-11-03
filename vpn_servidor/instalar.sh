#!/usr/bin/env bash
# Servidor VPN propio de GuardianIA (WireGuard) para Debian 12 — por ejemplo Google Cloud e2-micro gratis.
# Uso (en la máquina, como root):   sudo bash instalar.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Ejecute con sudo."; exit 1; }
AQUI="$(cd "$(dirname "$0")" && pwd)"
DIR=/etc/guardian-vpn
OPT=/opt/guardian-vpn
PUERTO_WG=51820
PUERTO_API=8844

echo "== 1/7 Paquetes (WireGuard, firewall, DNS propio) =="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard nftables unbound python3-venv openssl curl >/dev/null

echo "== 2/7 Claves del servidor =="
install -d -m 700 "$DIR"
umask 077
[[ -f $DIR/servidor.key ]] || wg genkey > "$DIR/servidor.key"
PUB=$(wg pubkey < "$DIR/servidor.key")
WAN=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
IP_PUB=$(curl -s -m 5 -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip || true)
[[ -n "$IP_PUB" ]] || IP_PUB=$(curl -s -m 8 https://api.ipify.org)
ZONA=$(curl -s -m 5 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}' || true)
REGION=${ZONA%-*}; [[ -n "$REGION" ]] || REGION="desconocida"
TIENE_V6=0; ip -6 route get 2001:4860:4860::8888 >/dev/null 2>&1 && TIENE_V6=1

echo "== 3/7 Túnel WireGuard =="
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
Address = 10.66.0.1/24, fd66::1/64
ListenPort = $PUERTO_WG
PrivateKey = $(cat "$DIR/servidor.key")
CONF
chmod 600 /etc/wireguard/wg0.conf
cat > /etc/sysctl.d/90-guardian-vpn.conf <<CONF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
CONF
sysctl -q --system

echo "== 4/7 Firewall (todo cerrado salvo SSH, VPN y API) =="
NAT6=""; [[ $TIENE_V6 -eq 1 ]] && NAT6="ip6 saddr fd66::/64 oifname \"$WAN\" masquerade"
cat > /etc/nftables.conf <<CONF
#!/usr/sbin/nft -f
flush ruleset
table inet guardian {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
    meta l4proto { icmp, ipv6-icmp } accept
    tcp dport 22 accept
    udp dport $PUERTO_WG accept
    tcp dport $PUERTO_API accept
    iifname "wg0" udp dport 53 accept
    iifname "wg0" tcp dport 53 accept
  }
  chain freno { }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" jump freno
    iifname "wg0" oifname "$WAN" ip saddr 10.66.0.0/24 accept
    $( [[ $TIENE_V6 -eq 1 ]] && echo "iifname \"wg0\" oifname \"$WAN\" ip6 saddr fd66::/64 accept" )
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr 10.66.0.0/24 oifname "$WAN" masquerade
    $NAT6
  }
}
CONF
systemctl enable -q --now nftables
nft -f /etc/nftables.conf

echo "== 5/7 DNS propio sin registros (Unbound) =="
cat > /etc/unbound/unbound.conf.d/guardian.conf <<CONF
server:
  interface: 127.0.0.1
  interface: 10.66.0.1
  interface: fd66::1
  access-control: 127.0.0.0/8 allow
  access-control: 10.66.0.0/24 allow
  access-control: fd66::/64 allow
  verbosity: 0
  log-queries: no
  log-replies: no
  hide-identity: yes
  hide-version: yes
  qname-minimisation: yes
  harden-dnssec-stripped: yes
  use-caps-for-id: yes
  prefetch: yes
  ip-freebind: yes
CONF
systemctl enable -q --now wg-quick@wg0
systemctl restart unbound

echo "== 6/7 API de altas (HTTPS, ficha secreta) =="
[[ -f $DIR/api.key ]] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=guardian-vpn" -keyout "$DIR/api.key" -out "$DIR/api.crt" 2>/dev/null
HUELLA=$(openssl x509 -in "$DIR/api.crt" -noout -fingerprint -sha256 | cut -d= -f2)
FICHA=$(openssl rand -base64 33 | tr -d '/+=' | cut -c1-40)
FICHA_SHA=$(printf '%s' "$FICHA" | sha256sum | cut -d' ' -f1)
cat > "$DIR/config.json" <<CONF
{"clave_publica": "$PUB", "endpoint": "$IP_PUB:$PUERTO_WG", "region": "$REGION",
 "puerto_api": $PUERTO_API, "ficha_sha256": "$FICHA_SHA", "ipv6": $TIENE_V6}
CONF
chmod 600 "$DIR/config.json"
python3 -m venv "$OPT"
"$OPT/bin/pip" install -q --upgrade pip
"$OPT/bin/pip" install -q "fastapi==0.115.*" "uvicorn==0.32.*"
install -m 644 "$AQUI/agente.py" "$OPT/agente.py"
cat > /etc/systemd/system/guardian-vpn.service <<CONF
[Unit]
Description=GuardianIA VPN (agente de altas)
After=network-online.target wg-quick@wg0.service
[Service]
ExecStart=$OPT/bin/python $OPT/agente.py
Environment=GUARDIAN_VPN_DIR=$DIR
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN
[Install]
WantedBy=multi-user.target
CONF
systemctl daemon-reload
systemctl enable -q --now guardian-vpn

echo "== 7/7 Sin registros =="
# El agente no registra accesos; journald guarda poco y por poco tiempo.
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nMaxRetentionSec=1day\nSystemMaxUse=50M\n' > /etc/systemd/journald.conf.d/guardian.conf
systemctl restart systemd-journald

cat <<FIN

  ✅ Servidor VPN de GuardianIA listo ($REGION)
  ─────────────────────────────────────────────
  Dirección de la API:  https://$IP_PUB:$PUERTO_API
  Huella del certificado (SHA-256):
      $HUELLA
  Ficha secreta (se muestra UNA sola vez; guárdela):
      $FICHA

  En GuardianIA (PC) → Protección → VPN → «Mi servidor VPN» → pegue estos tres datos.
  IPv6 en el servidor: $([[ $TIENE_V6 -eq 1 ]] && echo "sí" || echo "no (el IPv6 del túnel se descarta: sin fugas)")
FIN
