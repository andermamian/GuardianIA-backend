# Montar el servidor de la VPN (WireGuard)

Esta es la única pieza que GuardianIA no puede darle por software: hace falta una máquina con IP
pública. Un túnel necesita dos extremos, y el segundo tiene que existir en algún lado.

Con el servidor montado, el resto ya está hecho: el agente genera sus claves, el backend entrega la
configuración, el túnel se levanta solo y la interfaz verifica que su IP pública cambió de verdad.

## 1. Conseguir el servidor

Cualquier VPS pequeño sirve; WireGuard consume muy poco.

| Proveedor | Plan mínimo | Costo aproximado |
|---|---|---|
| Hetzner | CX22 | 4 EUR/mes (~19.000 COP) |
| DigitalOcean | Basic 512 MB | 4 USD/mes (~17.000 COP) |
| Oracle Cloud | Always Free (ARM) | gratis |
| Vultr | Regular 512 MB | 3,50 USD/mes |

Para servir a Colombia, elija una región en Miami, Bogotá o São Paulo: menos distancia, menos
latencia. La capa gratuita de Oracle alcanza de sobra para una sustentación y para uso personal.

## 2. Instalar WireGuard (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y wireguard
cd /etc/wireguard
umask 077
wg genkey | tee servidor.key | wg pubkey > servidor.pub
cat servidor.key servidor.pub      # anote ambas: la pública va a GuardianIA
```

Cree `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = <contenido de servidor.key>

# Enruta el tráfico de los clientes hacia internet y lo enmascara con la IP del servidor.
# Cambie eth0 por su interfaz real (véala con: ip route | grep default).
PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
```

Active el reenvío y levante el servicio:

```bash
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-wireguard.conf
sudo sysctl --system
sudo systemctl enable --now wg-quick@wg0
sudo ufw allow 51820/udp        # y abra ese puerto UDP en el panel del proveedor
```

## 3. Registrarlo en GuardianIA

En la carpeta del proyecto, con la clave **pública** del servidor:

```bash
python -m app.cli vpn-servidor \
  --id co-bog-real --ciudad "Bogotá" --pais CO \
  --endpoint 45.33.10.2:51820 \
  --clave-publica "LA_CLAVE_PUBLICA_DEL_SERVIDOR" \
  --ip-salida 45.33.10.2
```

`--ip-salida` es la IP pública del servidor y es la clave de todo: con ella se comprueba que su
tráfico realmente sale por ahí.

## 4. Autorizar su equipo en el servidor

Por seguridad, WireGuard solo acepta claves que usted autorizó. Obtenga la de su equipo:

```powershell
python guardian_agent.py vpn estado      # muestra la clave pública del equipo
```

Y en el servidor:

```bash
sudo wg set wg0 peer "CLAVE_PUBLICA_DEL_EQUIPO" allowed-ips 10.66.0.2/32
sudo wg-quick save wg0     # para que sobreviva a un reinicio
```

La IP `10.66.0.2` es la que GuardianIA le asignó a ese dispositivo; la ve en la respuesta del
registro o en la pantalla de VPN.

## 5. Conectar y comprobar

1. Instale WireGuard en su PC: <https://www.wireguard.com/install/>
2. En la app web, pestaña **VPN inteligente**, elija el servidor real y presione **Conectar**.
3. El agente recibe la orden en menos de un minuto, levanta el túnel y **verifica la IP pública**.

Sabrá que funciona porque la pantalla dirá **«VPN conectada y verificada»** e indicará que su IP
pasó de una a otra. Si la IP no cambia, dirá **«Sin túnel: tráfico sin cifrar»**, y eso también es
información útil: significa que algo del enrutamiento falló.

Compruébelo usted mismo en <https://ifconfig.me>: debe mostrar la IP del servidor.

## Por qué está diseñado así

- **La clave privada se genera en su equipo y nunca viaja.** Ni siquiera quien opere el servidor de
  GuardianIA puede descifrar su tráfico. Es la diferencia entre una VPN y un intermediario curioso.
- **`AllowedIPs = 0.0.0.0/0`** manda todo el tráfico por el túnel. Con una ruta parcial, el navegador
  seguiría saliendo por su conexión normal y la IP no cambiaría.
- **Nada se marca como conectado sin prueba.** El estado depende de que la IP pública haya cambiado,
  no de que el cliente lo afirme.
- **Cada dispositivo tiene su IP fija** dentro del túnel, así el servidor puede revocar uno sin
  afectar a los demás.

## Advertencia legal y práctica

Al montar una VPN, todo el tráfico de sus usuarios sale con la IP de su servidor. Si alguien la usa
para algo ilegal, las consultas llegan a usted. Para una app con usuarios reales, esto exige términos
de uso claros y una política de registros. Para su sustentación y uso personal no es un problema,
pero conviene que lo sepa antes de ofrecerla a terceros.
