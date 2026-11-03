"""Control de acceso basado en roles con permisos granulares.

La matriz vive en código (revisable en Git) y no en la base de datos:
nadie puede otorgarse permisos editando una fila.
"""
from __future__ import annotations

ROLES = ("user", "supervisor", "admin", "super_admin")
STAFF_ROLES = ("supervisor", "admin", "super_admin")
ROLE_LEVEL = {r: i for i, r in enumerate(ROLES)}

PERMISSIONS: dict[str, str] = {
    "dashboard:read": "Ver analítica y salud del sistema",
    "users:read": "Consultar usuarios",
    "users:write": "Suspender, reactivar y editar usuarios",
    "users:roles": "Cambiar roles",
    "security:read": "Ver alertas, bitácora y sesiones",
    "security:respond": "Resolver alertas, bloquear IP y revocar sesiones",
    "incidents:read": "Ver incidentes de emergencia",
    "incidents:manage": "Asignar y cerrar incidentes",
    "incidents:broadcast": "Enviar alertas masivas",
    "config:read": "Ver configuración",
    "config:decide": "Aprobar o rechazar recomendaciones de la IA",
    "health:thresholds": "Modificar umbrales clínicos de un usuario",
    "ops:backups": "Crear y verificar copias de seguridad",
    "ops:keys": "Rotar claves de cifrado",
    "support:read": "Ver tickets",
    "support:write": "Responder y asignar tickets",
    "ai:read": "Ver métricas de los modelos",
    "ai:train": "Entrenar las redes neuronales",
}

_SUPERVISOR = {"dashboard:read", "users:read", "security:read", "incidents:read", "incidents:manage",
               "config:read", "support:read", "support:write", "ai:read"}
# Entrenar cambia cómo detecta el sistema y consume CPU: es de administrador, no de supervisor.
_ADMIN = _SUPERVISOR | {"users:write", "security:respond", "config:decide", "health:thresholds",
                        "ops:backups", "incidents:broadcast", "ai:train"}
MATRIX: dict[str, set[str]] = {
    "user": set(),
    "supervisor": _SUPERVISOR,
    "admin": _ADMIN,
    "super_admin": set(PERMISSIONS),
}


def has_permission(role: str, perm: str) -> bool:
    return perm in MATRIX.get(role, set())


def can_manage(actor_role: str, target_role: str) -> bool:
    """Nadie gestiona a alguien de su mismo nivel o superior (salvo super_admin)."""
    if actor_role == "super_admin":
        return True
    return ROLE_LEVEL[actor_role] > ROLE_LEVEL[target_role]
