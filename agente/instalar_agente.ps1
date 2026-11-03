# GuardianIA - Instalacion del agente de proteccion en Windows
#
# Deja el agente corriendo como SYSTEM: el unico nivel con el que se puede leer todo el disco,
# incluidas las carpetas de otros usuarios y las areas protegidas.
#
#   Clic derecho sobre este archivo -> "Ejecutar con PowerShell" (como administrador)
#   o bien:  powershell -ExecutionPolicy Bypass -File .\instalar_agente.ps1
#
# Que hace, y por que:
#   1. Verifica privilegios. Sin administrador, el agente solo ve las carpetas del usuario actual.
#   2. Registra el agente contra su servidor con el token del dispositivo.
#   3. Crea una tarea programada que corre como SYSTEM al arrancar Windows.
#   4. Excluye SOLO la carpeta de cuarentena en Windows Defender. Es imprescindible: sin eso,
#      Defender detecta los archivos aislados y pelea con GuardianIA por el mismo archivo.
#      No se excluye nada mas: una exclusion amplia seria un agujero, no una comodidad.

param(
    [string]$Servidor = "https://127.0.0.1:8443",
    [string]$Token,          # opcional: normalmente se usa el codigo de 6 digitos
    [switch]$Desinstalar
)

$ErrorActionPreference = "Stop"
$NombreTarea = "GuardianIA-Agente"
$Cuarentena  = "$env:ProgramData\GuardianIA"

function Es-Administrador {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Buscar-Python {
    foreach ($c in @("python", "python3", "py")) {
        try {
            $v = & $c --version 2>&1
            if ($v -match "Python 3\.(\d+)") {
                if ([int]$Matches[1] -ge 10) { return (Get-Command $c).Source }
                Write-Host "  [!] $c es $v; se necesita Python 3.10 o superior" -ForegroundColor Yellow
            }
        } catch { }
    }
    throw "No encontre Python 3.10+. Instalelo desde https://python.org marcando 'Add to PATH'."
}

if (-not (Es-Administrador)) {
    Write-Host "Este script necesita privilegios de administrador." -ForegroundColor Red
    Write-Host "Cierre esta ventana y abra PowerShell con clic derecho -> 'Ejecutar como administrador'."
    Write-Host ""
    Write-Host "Sin administrador el agente igual funciona, pero solo revisa SUS carpetas:"
    Write-Host "  no puede analizar el disco completo ni aislar archivos de otros usuarios."
    exit 1
}

$AgenteDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script    = Join-Path $AgenteDir "guardian_agent.py"

if ($Desinstalar) {
    Write-Host "== Desinstalando el agente" -ForegroundColor Cyan
    schtasks /Delete /TN $NombreTarea /F 2>$null | Out-Null
    try { Remove-MpPreference -ExclusionPath $Cuarentena -ErrorAction SilentlyContinue } catch { }
    Write-Host "[OK] Tarea eliminada y exclusion retirada."
    Write-Host "     La cuarentena sigue en $Cuarentena. Revisela antes de borrarla:"
    Write-Host "     puede contener archivos suyos que quiera recuperar."
    exit 0
}

if (-not (Test-Path $Script)) { throw "No encuentro guardian_agent.py junto a este script." }

Write-Host "== GuardianIA - Instalacion del agente" -ForegroundColor Cyan
$Python = Buscar-Python
Write-Host "Python:   $Python"
Write-Host "Servidor: $Servidor"
Write-Host "Equipo:   $env:COMPUTERNAME ($env:PROCESSOR_IDENTIFIER)"

# --- 1. Vinculacion (codigo de 6 digitos, sin copiar tokens)
Write-Host ""
Write-Host "== Vinculando este equipo" -ForegroundColor Cyan
if ($Token) {
    & $Python $Script registrar --servidor $Servidor --token $Token
} else {
    Write-Host "1. Abra en el navegador:  $Servidor/app/#/dispositivos"
    Write-Host "2. Presione 'Vincular equipo nuevo'"
    Write-Host "3. Escriba aqui el codigo de 6 digitos que aparece (vence en 10 minutos)"
    Write-Host ""
    $Codigo = Read-Host "Codigo de 6 digitos"
    & $Python $Script vincular --servidor $Servidor --codigo $Codigo
}
if ($LASTEXITCODE -ne 0) { throw "La vinculacion fallo. Si el codigo vencio, genere uno nuevo y repita." }

# --- 3. Exclusion minima en Defender
Write-Host ""
Write-Host "== Configurando la convivencia con Windows Defender" -ForegroundColor Cyan
try {
    New-Item -ItemType Directory -Force -Path "$Cuarentena\cuarentena" | Out-Null
    Add-MpPreference -ExclusionPath "$Cuarentena\cuarentena"
    Write-Host "[OK] Excluida SOLO la carpeta de cuarentena: $Cuarentena\cuarentena"
    Write-Host "     Sin esto, Defender y GuardianIA pelean por el mismo archivo aislado."
    Write-Host "     El resto del disco lo sigue vigilando Defender con normalidad."
} catch {
    Write-Host "[!] No se pudo agregar la exclusion: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    Hagalo a mano en Seguridad de Windows -> Proteccion antivirus -> Exclusiones."
}

# --- 4. Tarea programada como SYSTEM
Write-Host ""
Write-Host "== Creando el servicio" -ForegroundColor Cyan
$Accion  = New-ScheduledTaskAction -Execute $Python -Argument "`"$Script`" servicio" -WorkingDirectory $AgenteDir
$Disparo = New-ScheduledTaskTrigger -AtStartup
$Cuenta  = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
# Se permite que corra con bateria: un portatil desconectado tambien puede infectarse.
$Ajustes = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0)

Register-ScheduledTask -TaskName $NombreTarea -Action $Accion -Trigger $Disparo `
    -Principal $Cuenta -Settings $Ajustes -Force | Out-Null
Start-ScheduledTask -TaskName $NombreTarea
Write-Host "[OK] Tarea '$NombreTarea' creada y ejecutandose como SYSTEM."

# --- 5. Analisis rapido inicial
Write-Host ""
Write-Host "== Primer analisis rapido" -ForegroundColor Cyan
& $Python $Script escanear --modo rapido --limite 800

Write-Host ""
Write-Host "Listo." -ForegroundColor Green
Write-Host "  Estado del agente:   $Python `"$Script`" estado"
Write-Host "  Disco completo:      $Python `"$Script`" escanear --modo completo"
Write-Host "  Desde la web:        $Servidor/app/#/proteccion/agente"
Write-Host "  Desinstalar:         .\instalar_agente.ps1 -Desinstalar"
Write-Host ""
Write-Host "Consejo: deje UNO de los dos vigilando en tiempo real (Defender o GuardianIA)." -ForegroundColor Yellow
Write-Host "Los dos a la vez revisan cada archivo dos veces y el equipo se siente lento."
