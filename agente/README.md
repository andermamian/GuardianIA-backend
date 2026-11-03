# Agente de protección GuardianIA

El componente que sí puede tocar el disco: analiza unidades completas, vigila en tiempo real y pone
en cuarentena. Corre como servicio del sistema.

## Por qué existe (y por qué el navegador no basta)

Un navegador no puede leer su disco ni borrar archivos: su aislamiento lo impide. Y está bien que así
sea, porque un sitio web capaz de hacerlo sería justo el problema que decimos resolver. Windows
Defender puede porque es un servicio con privilegios; este agente juega en esa liga.

```
agente con privilegios  ←→  backend  ←→  consola web
  (escanea, aísla)          (decide)      (usted ordena)
```

## Instalación en Windows (un comando)

Clic derecho en `instalar_agente.ps1` → «Ejecutar con PowerShell» **como administrador**:

```powershell
powershell -ExecutionPolicy Bypass -File .\instalar_agente.ps1 -Servidor http://127.0.0.1:8000
```

Hace cuatro cosas: verifica privilegios, registra el equipo, crea una tarea programada que corre
como **SYSTEM** al arrancar, y excluye **solo** la carpeta de cuarentena en Windows Defender.

Para desinstalar: `.\instalar_agente.ps1 -Desinstalar`

## Uso manual

```bash
python guardian_agent.py registrar --servidor http://127.0.0.1:8000 --token <token>
python guardian_agent.py escanear --modo completo            # todos los discos y memorias
python guardian_agent.py escanear --modo rapido              # descargas, temporales, escritorio
python guardian_agent.py escanear --modo personalizado --ruta "D:\\"
python guardian_agent.py servicio                            # tiempo real + tareas del servidor
python guardian_agent.py estado
```

Modos de rendimiento: `--rendimiento auto|turbo|silencioso`.

## Decisiones de seguridad

| Riesgo | Cómo se cierra |
|---|---|
| Servidor comprometido ordenando cosas | Lista cerrada de tareas: escanear, restaurar, eliminar. Nada más. No existe «ejecuta esto» |
| Borrado por error | El servidor nunca borra. Eliminar es decisión de la persona sobre un archivo ya aislado |
| Falso positivo que rompe el equipo | Rutas del sistema intocables: aunque se ordene, el agente se niega |
| Falso positivo que borra su trabajo | Solo se aísla lo **malicioso**; lo sospechoso se reporta y se deja quieto |
| Cuarentena que infecta | Cada archivo se cifra, pierde su extensión y queda con permisos 600, sin ejecución |
| Fuga de documentos privados | Nunca se sube un archivo: solo huella, cabecera, entropía y cadenas |
| Token robado del archivo de config | Permisos 600 y, con privilegios, guardado en ProgramData, no en la carpeta del usuario |

## Rendimiento

Un antivirus que vuelve lento el equipo termina desinstalado, y entonces no protege nada. Por eso:

- **Prioriza por riesgo**: ejecutables en Descargas y archivos modificados esta semana van primero.
  Si el análisis se corta, ya revisó lo que importaba.
- **Salta lo que no cambió** desde el último análisis (fecha y tamaño).
- **Cede recursos**: mide la CPU cada 5 segundos y ajusta hilos y pausas. En un Ryzen de 16 hilos usa
  8 cuando el equipo está libre y baja a 2 apenas usted empieza a trabajar.

## Convivencia con Windows Defender

Pueden convivir, pero si ambos vigilan en tiempo real cada archivo se revisa dos veces y el equipo se
siente lento. Deje uno de los dos con vigilancia activa; el otro sirve igual para análisis a demanda.
