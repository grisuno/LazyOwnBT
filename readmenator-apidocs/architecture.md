# LazyOwnBT Architecture and Execution Flows

[Back to index](index.md)

## Architecture Overview

7 components stacked in 3 dependency tiers (weighted Eades-Lin-Smyth ordering: arrows point from dependent to dependency, top to bottom). Labels are import counts, thick arrows the top quartile; 0 transitively implied edges are omitted. Dashed red arrows are upward dependencies: the smallest set of imports that closes every cycle and breaks the layering. Cyan components hold entry points. Interactive version: `readmenator-apidocs/index.html#/flows`.

Upward dependencies to fix first: `lazyownbt: web` -> `lazyownbt: main` (1 imports)

```mermaid
flowchart TB
    classDef cycle fill:#1f1530,stroke:#f472b6,color:#fce7f3,stroke-width:2px;
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    subgraph lane_0["Tier 1 - entry / orchestration"]
        direction LR
        n_c1["lazyownbt: main<br/>2 files, 24 symbols<br/>Presentation / entry"]:::entry
        n_d_static["static<br/>3 files, 11 symbols<br/>Core / utility"]:::default
        n_d_skills["skills<br/>1 files, 13 symbols<br/>Core / utility"]:::default
        n_d_lazyownbt["lazyownbt<br/>1 files, 0 symbols<br/>Core / utility"]:::default
        n_d__root_["(root)<br/>2 files, 193 symbols<br/>Core / utility"]:::entry
    end
    subgraph lane_1["Tier 2"]
        direction LR
        n_c0["lazyownbt: web<br/>4 files, 41 symbols<br/>Presentation / entry"]:::cycle
    end
    subgraph lane_2["Tier 3 - foundation"]
        direction LR
        n_c2["lazyownbt: security<br/>1 files, 6 symbols<br/>Core / utility"]:::default
    end
    n_c0 -->|"1"| n_c2
    n_c1 ==>|"2"| n_c0
    n_c1 <-.-|"1 upward"| n_c0
    linkStyle 2 stroke:#f87171,stroke-width:2px;
    n_c1 ~~~ n_c0
    n_c0 ~~~ n_c2
```

---

## Execution Flows

Entry points are scored from `__main__` guards, `main` functions, entry-style names and files, and call-graph sources. Each flow walks resolved calls in call-site order (depth <= 4, <= 40 steps); numbers give the call order, dashed arrows revisit an already expanded callee, red arrows are recursion. Interactive version with zoom and per-node docs: `readmenator-apidocs/index.html#/flows`.

### `app (__main__)`

`app.py:5313`, score 8: `if __name__ == "__main__"` guard.

Control flow:

```mermaid
flowchart TB
    classDef decision fill:#1e1b4b,stroke:#a78bfa,color:#ede9fe;
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    n_s1(["start app (__main__)"]):::entry
    n_s2{"os.geteuid() != 0?"}:::decision
    n_s3["style()<br/>Equivalente funcional de la antigua #96;cmd2.sty..."]:::default
    n_s4["style()<br/>Equivalente funcional de la antigua #96;cmd2.sty..."]:::default
    n_s5["LazyOwnApp()<br/>Interfaz de línea de comandos para LazyOwn Bl..."]:::default
    n_s6(["end"]):::entry
    n_s1 --> n_s2
    n_s2 -->|"yes"| n_s3
    n_s2 -->|"no"| n_s4
    n_s3 --> n_s5
    n_s4 --> n_s5
    n_s5 --> n_s6
```

Call tree:

```mermaid
flowchart LR
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    n_app_py___main_["app (__main__)<br/>app.py"]:::entry
    n_app_py__LazyOwnApp["app.LazyOwnApp<br/>Interfaz de línea de comandos para LazyOwn Bl...<br/>app.py:3453"]:::default
    n_app_py___main_ -->|"1"| n_app_py__LazyOwnApp
```

### `web (__main__)`

`lazyownbt/web.py:258`, score 8: `if __name__ == "__main__"` guard.

Call tree:

```mermaid
flowchart LR
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    classDef external fill:#1a1530,stroke:#a78bfa,color:#ede9fe;
    n_lazyownbt_web_py___main_["web (__main__)<br/>web.py"]:::entry
    n_lazyownbt_web_py__run["web.run<br/>Punto de entrada CLI: respeta SEC-003.1 y SEC...<br/>web.py:236"]:::default
    n_lazyownbt_web_py___default_flask_env_if_unset["web._default_flask_env_if_unset<br/>UX: si FLASK_ENV no está definida, asume deve...<br/>web.py:220"]:::default
    n_lazyownbt_config_py__load_settings["config.load_settings<br/>Carga y valida la configuración.<br/>config.py:125"]:::external
    n_lazyownbt_config_py___load_dotenv["config._load_dotenv<br/>Carga .env si existe.<br/>config.py:32"]:::external
    n_lazyownbt_config_py__ConfigError["config.ConfigError<br/>Error de configuración.<br/>config.py:28"]:::external
    n_lazyownbt_config_py__Settings["config.Settings<br/>Configuración inmutable de la aplicación.<br/>config.py:104"]:::external
    n_lazyownbt_config_py___resolve_jwt_secret["config._resolve_jwt_secret<br/>Resuelve el secreto de JWT según SEC-001.2 y...<br/>config.py:39"]:::external
    n_lazyownbt_config_py___resolve_admin_password_hash["config._resolve_admin_password_hash<br/>Resuelve el hash de la contraseña admin según...<br/>config.py:73"]:::external
    n_lazyownbt_web_py__create_app["web.create_app<br/>Crea y configura la app Flask.<br/>web.py:66"]:::default
    n_lazyownbt_actions_py__ActionRegistry["actions.ActionRegistry<br/>Registro cerrado de acciones permitidas (SEC-...<br/>actions.py:28"]:::external
    n_lazyownbt_audit_py__AuditLog["audit.AuditLog<br/>Log de auditoría respaldado por SQLite.<br/>audit.py:33"]:::external
    n_lazyownbt_web_py___register_default_actions["web._register_default_actions<br/>Carga las acciones por defecto.<br/>web.py:55"]:::default
    n_lazyownbt_handlers_py__build_default_handlers["handlers.build_default_handlers<br/>handlers.py:84"]:::external
    n_lazyownbt_actions_py__register["actions.ActionRegistry.register<br/>actions.py:35"]:::external
    n_lazyownbt_security_py__install_secrets_filter["security.install_secrets_filter<br/>Instala el SecretsFilter en un logger.<br/>security.py:51"]:::external
    n_lazyownbt_security_py__SecretsFilter["security.SecretsFilter<br/>Filtro de logging que redacta valores de secr...<br/>security.py:13"]:::external
    n_lazyownbt_web_py___build_csp["web._build_csp<br/>CSP estricta sin hashes hardcodeados (SEC-003...<br/>web.py:38"]:::default
    n_lazyownbt_web_py___register_routes["web._register_routes<br/>web.py:114"]:::default
    n_lazyownbt_web_py___main_ -->|"1"| n_lazyownbt_web_py__run
    n_lazyownbt_web_py__run -->|"1"| n_lazyownbt_web_py___default_flask_env_if_unset
    n_lazyownbt_web_py__run -->|"2"| n_lazyownbt_config_py__load_settings
    n_lazyownbt_config_py__load_settings -->|"1"| n_lazyownbt_config_py___load_dotenv
    n_lazyownbt_config_py__load_settings -->|"2"| n_lazyownbt_config_py__ConfigError
    n_lazyownbt_config_py__load_settings -->|"3"| n_lazyownbt_config_py__Settings
    n_lazyownbt_config_py__load_settings -->|"4"| n_lazyownbt_config_py___resolve_jwt_secret
    n_lazyownbt_config_py___resolve_jwt_secret -.-> n_lazyownbt_config_py__ConfigError
    n_lazyownbt_config_py__load_settings -->|"5"| n_lazyownbt_config_py___resolve_admin_password_hash
    n_lazyownbt_config_py___resolve_admin_password_hash -.-> n_lazyownbt_config_py__ConfigError
    n_lazyownbt_web_py__run -->|"3"| n_lazyownbt_web_py__create_app
    n_lazyownbt_web_py__create_app -.-> n_lazyownbt_config_py__load_settings
    n_lazyownbt_web_py__create_app -->|"1"| n_lazyownbt_actions_py__ActionRegistry
    n_lazyownbt_web_py__create_app -->|"2"| n_lazyownbt_audit_py__AuditLog
    n_lazyownbt_web_py__create_app -->|"3"| n_lazyownbt_web_py___register_default_actions
    n_lazyownbt_web_py___register_default_actions -->|"1"| n_lazyownbt_handlers_py__build_default_handlers
    n_lazyownbt_web_py___register_default_actions -->|"2"| n_lazyownbt_actions_py__register
    n_lazyownbt_web_py__create_app -->|"4"| n_lazyownbt_security_py__install_secrets_filter
    n_lazyownbt_security_py__install_secrets_filter -->|"1"| n_lazyownbt_security_py__SecretsFilter
    n_lazyownbt_web_py__create_app -->|"5"| n_lazyownbt_web_py___build_csp
    n_lazyownbt_web_py__create_app -->|"6"| n_lazyownbt_web_py___register_routes
```

Cross-file sequence:

```mermaid
sequenceDiagram
    autonumber
    participant p_lazyownbt_web_py as web.py
    participant p_lazyownbt_config_py as config.py
    participant p_lazyownbt_actions_py as actions.py
    participant p_lazyownbt_audit_py as audit.py
    participant p_lazyownbt_handlers_py as handlers.py
    participant p_lazyownbt_security_py as security.py
    p_lazyownbt_web_py->>p_lazyownbt_config_py: load_settings()
    p_lazyownbt_web_py->>p_lazyownbt_actions_py: ActionRegistry()
    p_lazyownbt_web_py->>p_lazyownbt_audit_py: AuditLog()
    p_lazyownbt_web_py->>p_lazyownbt_handlers_py: build_default_handlers()
    p_lazyownbt_web_py->>p_lazyownbt_actions_py: ActionRegistry.register()
    p_lazyownbt_web_py->>p_lazyownbt_security_py: install_secrets_filter()
```

### `main (__main__)`

`main.py:287`, score 8: `if __name__ == "__main__"` guard.

Control flow:

```mermaid
flowchart TB
    classDef decision fill:#1e1b4b,stroke:#a78bfa,color:#ede9fe;
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    classDef stop fill:#3f1d1d,stroke:#f87171,color:#fee2e2;
    n_s1(["start main (__main__)"]):::entry
    n_s2["get(), _default_flask_env_if_unset(), load_settings()<br/>UX: si FLASK_ENV no está definida, asume deve..."]:::default
    n_s3{"args.debug and (not settings.is_development)?"}:::decision
    n_s4(["raise SystemExit"]):::stop
    n_s5{"args.host not in ('127.0.0.1', '::1', 'localhost')?"}:::decision
    n_s6["build_app(), run()<br/>Construye la app final reutilizando :func:#96;cr..."]:::default
    n_s7(["end"]):::entry
    n_s1 --> n_s2
    n_s2 --> n_s3
    n_s3 -->|"yes"| n_s4
    n_s3 -->|"no"| n_s5
    n_s5 -->|"yes"| n_s6
    n_s5 -->|"no"| n_s6
    n_s6 --> n_s7
```

Call tree:

```mermaid
flowchart LR
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    classDef external fill:#1a1530,stroke:#a78bfa,color:#ede9fe;
    n_main_py___main_["main (__main__)<br/>main.py"]:::entry
    n_lazyownbt_web_py___default_flask_env_if_unset["web._default_flask_env_if_unset<br/>UX: si FLASK_ENV no está definida, asume deve...<br/>web.py:220"]:::external
    n_lazyownbt_config_py__load_settings["config.load_settings<br/>Carga y valida la configuración.<br/>config.py:125"]:::external
    n_lazyownbt_config_py___load_dotenv["config._load_dotenv<br/>Carga .env si existe.<br/>config.py:32"]:::external
    n_lazyownbt_config_py__ConfigError["config.ConfigError<br/>Error de configuración.<br/>config.py:28"]:::external
    n_lazyownbt_config_py__Settings["config.Settings<br/>Configuración inmutable de la aplicación.<br/>config.py:104"]:::external
    n_lazyownbt_config_py___resolve_jwt_secret["config._resolve_jwt_secret<br/>Resuelve el secreto de JWT según SEC-001.2 y...<br/>config.py:39"]:::external
    n_lazyownbt_config_py___resolve_admin_password_hash["config._resolve_admin_password_hash<br/>Resuelve el hash de la contraseña admin según...<br/>config.py:73"]:::external
    n_main_py__build_app["main.build_app<br/>Construye la app final reutilizando :func:#96;cr...<br/>main.py:260"]:::default
    n_lazyownbt_web_py__create_app["web.create_app<br/>Crea y configura la app Flask.<br/>web.py:66"]:::external
    n_lazyownbt_actions_py__ActionRegistry["actions.ActionRegistry<br/>Registro cerrado de acciones permitidas (SEC-...<br/>actions.py:28"]:::external
    n_lazyownbt_audit_py__AuditLog["audit.AuditLog<br/>Log de auditoría respaldado por SQLite.<br/>audit.py:33"]:::external
    n_lazyownbt_web_py___register_default_actions["web._register_default_actions<br/>Carga las acciones por defecto.<br/>web.py:55"]:::external
    n_lazyownbt_handlers_py__build_default_handlers["handlers.build_default_handlers<br/>handlers.py:84"]:::external
    n_lazyownbt_actions_py__register["actions.ActionRegistry.register<br/>actions.py:35"]:::external
    n_lazyownbt_security_py__install_secrets_filter["security.install_secrets_filter<br/>Instala el SecretsFilter en un logger.<br/>security.py:51"]:::external
    n_lazyownbt_security_py__SecretsFilter["security.SecretsFilter<br/>Filtro de logging que redacta valores de secr...<br/>security.py:13"]:::external
    n_lazyownbt_web_py___build_csp["web._build_csp<br/>CSP estricta sin hashes hardcodeados (SEC-003...<br/>web.py:38"]:::external
    n_lazyownbt_web_py___register_routes["web._register_routes<br/>web.py:114"]:::external
    n_main_py__Database["main.Database<br/>Acceso de solo-lectura a la base de datos SQL...<br/>main.py:42"]:::default
    n_main_py___register_data_routes["main._register_data_routes<br/>Añade las rutas de solo-lectura sobre la BD.<br/>main.py:200"]:::default
    n_main_py___main_ -->|"1"| n_lazyownbt_web_py___default_flask_env_if_unset
    n_main_py___main_ -->|"2"| n_lazyownbt_config_py__load_settings
    n_lazyownbt_config_py__load_settings -->|"1"| n_lazyownbt_config_py___load_dotenv
    n_lazyownbt_config_py__load_settings -->|"2"| n_lazyownbt_config_py__ConfigError
    n_lazyownbt_config_py__load_settings -->|"3"| n_lazyownbt_config_py__Settings
    n_lazyownbt_config_py__load_settings -->|"4"| n_lazyownbt_config_py___resolve_jwt_secret
    n_lazyownbt_config_py___resolve_jwt_secret -.-> n_lazyownbt_config_py__ConfigError
    n_lazyownbt_config_py__load_settings -->|"5"| n_lazyownbt_config_py___resolve_admin_password_hash
    n_lazyownbt_config_py___resolve_admin_password_hash -.-> n_lazyownbt_config_py__ConfigError
    n_main_py___main_ -->|"3"| n_main_py__build_app
    n_main_py__build_app -.-> n_lazyownbt_config_py__load_settings
    n_main_py__build_app -->|"1"| n_lazyownbt_web_py__create_app
    n_lazyownbt_web_py__create_app -.-> n_lazyownbt_config_py__load_settings
    n_lazyownbt_web_py__create_app -->|"1"| n_lazyownbt_actions_py__ActionRegistry
    n_lazyownbt_web_py__create_app -->|"2"| n_lazyownbt_audit_py__AuditLog
    n_lazyownbt_web_py__create_app -->|"3"| n_lazyownbt_web_py___register_default_actions
    n_lazyownbt_web_py___register_default_actions -->|"1"| n_lazyownbt_handlers_py__build_default_handlers
    n_lazyownbt_web_py___register_default_actions -->|"2"| n_lazyownbt_actions_py__register
    n_lazyownbt_web_py__create_app -->|"4"| n_lazyownbt_security_py__install_secrets_filter
    n_lazyownbt_security_py__install_secrets_filter -->|"1"| n_lazyownbt_security_py__SecretsFilter
    n_lazyownbt_web_py__create_app -->|"5"| n_lazyownbt_web_py___build_csp
    n_lazyownbt_web_py__create_app -->|"6"| n_lazyownbt_web_py___register_routes
    n_main_py__build_app -->|"2"| n_main_py__Database
    n_main_py__build_app -->|"3"| n_main_py___register_data_routes
```

Cross-file sequence:

```mermaid
sequenceDiagram
    autonumber
    participant p_main_py as main.py
    participant p_lazyownbt_web_py as web.py
    participant p_lazyownbt_config_py as config.py
    participant p_lazyownbt_actions_py as actions.py
    participant p_lazyownbt_audit_py as audit.py
    participant p_lazyownbt_handlers_py as handlers.py
    participant p_lazyownbt_security_py as security.py
    p_main_py->>p_lazyownbt_web_py: _default_flask_env_if_unset()
    p_main_py->>p_lazyownbt_config_py: load_settings()
    p_main_py->>p_lazyownbt_web_py: create_app()
    p_lazyownbt_web_py->>p_lazyownbt_actions_py: ActionRegistry()
    p_lazyownbt_web_py->>p_lazyownbt_audit_py: AuditLog()
    p_lazyownbt_web_py->>p_lazyownbt_handlers_py: build_default_handlers()
    p_lazyownbt_web_py->>p_lazyownbt_actions_py: ActionRegistry.register()
    p_lazyownbt_web_py->>p_lazyownbt_security_py: install_secrets_filter()
```

---
