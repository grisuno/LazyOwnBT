# `lazyownbt`

> Source: [lazyownbt/__init__.py:1](../../lazyownbt/__init__.py#L1) | language `py` | coverage 100.0% | [API index](../index.md)

LazyOwnBT — Blue Team defensive framework for Linux.

Estructura de paquetes:
- lazyownbt.config    : carga de configuración desde env + .env
- lazyownbt.security  : SecretsFilter y validadores de secretos
- lazyownbt.actions   : registro cerrado de acciones permitidas
- lazyownbt.audit     : registro de auditoría de acciones
- lazyownbt.web       : factory de la app Flask (reemplaza al main.py monolítico)
- lazyownbt.cli       : re-export de la app cmd2 original (en app.py) — se moverá
                        a un módulo dedicado en una iteración futura.
