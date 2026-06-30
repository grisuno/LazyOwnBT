"""LazyOwnBT — Blue Team defensive framework for Linux.

Estructura de paquetes:
- lazyownbt.config    : carga de configuración desde env + .env
- lazyownbt.security  : SecretsFilter y validadores de secretos
- lazyownbt.actions   : registro cerrado de acciones permitidas
- lazyownbt.audit     : registro de auditoría de acciones
- lazyownbt.web       : factory de la app Flask (reemplaza al main.py monolítico)
- lazyownbt.cli       : re-export de la app cmd2 original (en app.py) — se moverá
                        a un módulo dedicado en una iteración futura.
"""

__version__ = "1.0.0"
