"""Planes y funcionalidades — idénticos a MembershipManager.kt para que app y API coincidan."""
from __future__ import annotations

# La VPN básica (WARP, .conf propio, Tor) es gratis: la privacidad es seguridad personal, igual que el SOS.
BASIC_FEATURES = {"basic_threat_detection", "basic_optimization", "basic_chatbot", "basic_vpn"}
PREMIUM_FEATURES = {"advanced_threat_detection", "full_optimization", "advanced_chatbot",
                    "real_time_monitoring"}
ENTERPRISE_FEATURES = {"real_time_threat_detection", "predictive_optimization", "personalized_chatbot",
                       "premium_vpn", "forensic_analysis", "priority_support", "advanced_analytics"}

PLANS = {
    "BASIC": {"level": 0, "display_name": "Básico", "price": "Gratis", "price_cop": 0,
              "description": "Funcionalidades básicas de Guardian IA + VPN gratis", "features": BASIC_FEATURES},
    "PREMIUM": {"level": 1, "display_name": "Premium", "price": "$9.99/mes", "price_cop": 39900,
                "description": "Funcionalidades avanzadas + VPN básica",
                "features": BASIC_FEATURES | PREMIUM_FEATURES},
    "ENTERPRISE": {"level": 2, "display_name": "Enterprise", "price": "$19.99/mes", "price_cop": 79900,
                   "description": "Todas las funcionalidades + VPN premium + Soporte prioritario",
                   "features": BASIC_FEATURES | PREMIUM_FEATURES | ENTERPRISE_FEATURES},
}

PRODUCT_TO_PLAN = {"guardian_premium_monthly": "PREMIUM", "guardian_enterprise_monthly": "ENTERPRISE"}

# Las funciones de seguridad personal NUNCA van detrás de un pago:
# SOS, contactos de emergencia, alertas de signos vitales críticos y antirrobo básico son gratis.
ALWAYS_FREE = {"sos", "emergency_contacts", "critical_vital_alerts", "device_locate"}


def features_for(plan: str) -> set[str]:
    return PLANS.get(plan, PLANS["BASIC"])["features"]
