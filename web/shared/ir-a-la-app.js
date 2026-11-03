// La parte después de # nunca llega al servidor, así que la redirección se completa aquí:
// 127.0.0.1:8000/#/asistente  →  /app/#/asistente   (y las rutas de la consola, a /consola/).
const RUTAS_CONSOLA = ["resumen", "incidentes", "alertas", "usuarios", "recomendaciones", "seguridad", "operaciones", "modelos"];
const ruta = location.hash.replace(/^#\/?/, "").split("/")[0];
const destino = RUTAS_CONSOLA.includes(ruta) ? "/consola/" : "/app/";
location.replace(destino + location.hash);
